import {AppStore} from "../AppStore";
import {Component, OnInit} from "angular2/core";
import {fetchExplore} from "../actions";
import {RouterLink} from "angular2/router";

@Component({
    directives: [RouterLink],
    template: `
    <div class="bldr-explore">
        <h1>Explore</h1>
        <ul>
            <li *ngFor="#item of store.getState().explore.packages">
                <a [routerLink]="['PackagesForName', { name: item.name }]">
                    <span class="title">{{item.name}}</span>
                    <div class="info">
                        <span class="stars">{{item.starCount}}</span>
                    </div>
                </a>
            </li>
        </ul>
    </div>`,
})
export class ExplorePageComponent implements OnInit {
    constructor(private store: AppStore) { }
    ngOnInit() {
        this.store.dispatch(fetchExplore());
    }
}
