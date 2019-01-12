---
title: Introducing the Install Hook!
date: 2019-03-04
author: Matt Wrock
tags: supervisor, packaging
category: update
classes: body-article
---

This latest 0.99.99 release introduces a new `hook` to package authors: the `install` hook. The `install` hook runs when a package is first installed. This hook is unique in that it runs outside of a service or census context. With all other hooks, like `init` and `run` just to name a couple, the owning package must be loaded as a Supervisor service in order to execute the hook's behavior. The `install` hook can be packaged with any package regardless of whether it will run as a service and will execute when the package is installed. This installation may occur completely separate from any running Supervisor. For instance it could be triggered by a `hab pkg install` command but may also be triggered by a Supervisor's `hab svc load` if the package has not yet been installed. Further, it could be a dependency of another package being installed. Because the package does not need to run as a service, any uninstalled package with an `install` hook in the dependency tree of an installing package will have this hook executed as part of the parent installation.

## Why a new hook?

Sometimes installing software involves much more than simply laying files on disk. In many cases, simply extracting the files packaged in a `hart` file to the `/hab/pkgs` folders and ensuring that some environment variables are set at runtime are all that is needed for an application to behave. However in some cases, there may be required system API calls needed to ensure that software components are correctly registered with certain OS sub systems. This is often the case with Windows applications which may require registry keys to be set, Windows features to be enabled or complicated install scripts and binaries to run before the software can be considered installed and ready to use.

Today we manage these kinds of applications in Habitat by including this installation behavior inside of an `init` or `run` hook. This has worked but what if the application is a command line tool, a library, or a stand alone application that runs outside of a Supervisor? In such cases, you must deploy the application as a service and include a `run` hook that simply spins and sleeps. Even if the application is a service, what if it has dependencies like IIS or COM components that require the execution of scripts to fully register and configure those key dependencies. Well we either bundle those dependencies with the parent app or include their installation scripts with the parent package requiring the parent application to "know" intimate details about its dependencies.

With the `install` hook we can now break these applications up so that any installation behavior needed in a dependant package can be managed by that package. This also means that one can install Habitat packages that run as stand-alone applications and not be required to run them as services in order to execute their installation scripts.

## An example install hook scenario

To illustrate where an `install` hook may be convenient, I'll use a [legacy Windows web application](https://github.com/habitat-sh/sqlwebadmin) that we use in some Habitat demonstrations. This application requires IIS and ASP.Net 3.5 as well as a dependency on a COM library. Its `pkg_deps` looks like:

```
$pkg_deps=@("core/dsc-core", "core/sql-dmo")
```

Its `init` hook registers the COM component packaged in the `sql-dmo` package:

```
."$env:SystemRoot\SysWow64\regsvr32.exe" /s "{{pkgPathFor "core/sql-dmo"}}\Program Files (x86)\Microsoft SQL Server\80\Tools\Binn\sqldmo.dll"
```

So my web application needs to know that its `sql-dmo` dependency is COM based and must be aware of how such dependencies are registered as well as the exact files in the dependent package that must be referenced.

It's `run` hook uses the `dsc-core` dependency to execute the following DSC configuration:

```
WindowsFeature netfx3 
{ 
    Ensure = "Present"
    Name = "NET-Framework-Core"
    {{#if cfg.netfx3_source}}
        Source = "{{cfg.netfx3_source}}"
    {{/if}}
}

WindowsFeature ASP 
{ 
    Ensure = "Present"
    Name = "WEB-ASP-NET"
}

WindowsFeature static_content 
{ 
    Ensure = "Present"
    Name = "WEB-STATIC-CONTENT"
}
```

This makes sure that the .NET 3.5 runtime is installed, IIS is enabled, and the ASP.Net ISAPI filters are configured and that additionally the `WEB-STATIC-CONTENT` feature is enabled so that IIS can serve images, stylesheets and static `html` files.

What if I wanted to install several applications that depended on the same .NET 3.5 framework or leveraged IIS or ASP.Net? Each application would need to include this same DSC (or equivelent) behavior.

Let's see how this works differently with the `install` hook.

In this case my web application would not need an `install` hook, but if I could have dependencies with `install` hooks, my `pkg_deps` might look like this:

```
$pkg_deps=@("core/dsc-core", "mwrock/sql-dmo", "mwrock/iis-webserverrole", "mwrock/dotnet-35sp1-runtime", "mwrock/iis-aspnet35")
```

I'm not ready to commit these dependencies to our `core` origin so they find their home, for now, in my personal `mwrock` origin. I still need `dsc-core` to configure my app_pool with IIS, but that is fine since it is an application specific concern. I'm using a new `sql-dmo` package (in my own origin for now) that has an `install` hook which can register itself:

```
."$env:SystemRoot\SysWow64\regsvr32.exe" /s "{{pkg.path}}\Program Files (x86)\Microsoft SQL Server\80\Tools\Binn\sqldmo.dll"
```

Now my application does not need to concern itself at all with this detail.

Additionally, I now have dependencies for IIS, the .Net 3.5 framework and a package that enables ASP.Net to be configured into IIS. Each of these dependencies have an `install` hook that enables the appropriate Windows feature(s). As an example, here is the `install` hook for the `iis-webserverrole` package:


```
function Test-Feature {
    $(dism /online /get-featureinfo /featurename:IIS-WebServerRole) -contains "State : Enabled"
}

if (!Test-Feature) {
    dism /online /enable-feature /featurename:IIS-WebServerRole
    if (!Test-Feature) {
        exit 1
    }
}
```

This uses `dism` to check and enable our Windows feature. Not as elegant as DSC but I know this will work back to a vanilla 2008 R2 or Windows 7 OS. If for some reason, enabling the feature is not succesful, I make sure that the hook exits with a non `0` exit code. Depending on what went wrong, `dism` will often exit succesfully even if the feature enablement was not succesful. If the `install` hook returns a non `0` exit code, Habitat considers the `install` hook execution to be a failure and will retry whenever attempting to load the package or any other package that declares a dependency on this package.

## Templating considerations

One can use handlebar templating syntax in an `install` hook just like any other hook. However because the hook compilation occurs outside of any running Supervisor's census ring, the `install` hook and any configuration templates they reference will not have access to package `binds` or the `sys` namespace.

Another important difference with the `install` hook is that it should not reference configuration files located in `{{pkg.svc_config_path}}` - those rendered from a plan's `config` folder. Instead, the`install` hook has access to a new `pkg` property: `{{pkg.svc_config_install_path}}` which is the destination of rendered templates located in a plan's `config_install` folder. This ensures that templates that are rerendered due to configuratino changes in a running Supervisor will not trigger a service restart if they only impact the installatin of a package.

## Docker exporter behavior

One other behavior change that comes with the `install` hook is that the exporter will execute the `install` hook as part of the Docker image build. This is especially helpful when a service has install behavior that takes a long time to run. Currently if this behavior is in an `init` hook, the installation will occur on every `docker run` of the image but with an `install` hook it can be a one time operation that occurs during the export operation.

We have added two new Docker exporter arguments to support some common installation scenarios:

```
--memory
--user-toml
```

To illustrate when you would use these arguments, imagine installing something like SQL Server. If you are using Docker from a Windows 10 dev environment, the default amount of memory allocated to a container is 1GB and the default service account configured to run SQL Server in the `core/sqlserver` plan is `NT AUTHORITY\Network Service`. However, installing SQL Server will likely fail with only a single GB of RAM and a container based SQL Server install should run under `NT AUTHORITY\SYSTEM`. I can use the `--memory` argument to set an alternate amount of memory like `2gb` and I can supply a `user.toml` file that overrides the default `svc_account`: `svc_account="NT AUTHORITY\\SYSTEM"` and pass the exporter's file path to the `--user-toml` argument.

## Enabling the `INSTALL_HOOK` Habitat feature

The `install` hook is currently an "experimental" Habitat feature and must be enabled in order for any of the `install` hook behavior to run. To enable this feature, set the `HAB_FEAT_INSTALL_HOOK` environment variable to any value. This must be set in the following contexts:

* shell - to enable it for cli commands like `hab pkg install` and `hab pkg export docker`
* Supervisor service - to enable the execution of any `install` hooks when the Supervisor loads an uninstalled package
* Studio - to ensure that configuration templates located in the `config_install` folder are included in a built package's `hart`.
