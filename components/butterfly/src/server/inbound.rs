// Copyright (c) 2016-2017 Chef Software Inc. and/or applicable contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The inbound thread.
//!
//! This module handles all the inbound SWIM messages.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::thread;

use cpu_time::ThreadTime;
use prometheus::{CounterVec, GaugeVec};
use time::{Duration, SteadyTime};

use super::AckSender;
use member::Health;
use server::{outbound, Server};
use swim::{Ack, Ping, PingReq, Swim, SwimKind};
use trace::TraceKind;

lazy_static! {
    static ref SWIM_MESSAGES_RECEIVED: CounterVec = register_counter_vec!(
        "hab_butterfly_swim_messages_received_total",
        "Total number of SWIM messages received",
        &["type"]
    )
    .unwrap();
    static ref SWIM_BYTES_RECEIVED: GaugeVec = register_gauge_vec!(
        "hab_butterfly_swim_received_bytes",
        "SWIM message size received in bytes",
        &["type"]
    )
    .unwrap();
    static ref CPU_TIME: GaugeVec = register_gauge_vec!(
        "hab_butterfly_cpu_time_seconds",
        "CPU time, organized by thread",
        &["thread"]
    )
    .unwrap();
}

/// Takes the Server and a channel to send received Acks to the outbound thread.
pub struct Inbound {
    pub server: Server,
    pub socket: UdpSocket,
    pub tx_outbound: AckSender,
}

impl Inbound {
    /// Create a new Inbound.
    pub fn new(server: Server, socket: UdpSocket, tx_outbound: AckSender) -> Inbound {
        Inbound {
            server: server,
            socket: socket,
            tx_outbound: tx_outbound,
        }
    }

    /// Run the thread. Listens for messages up to 1k in size, and then processes them accordingly.
    pub fn run(&self) {
        let mut recv_buffer: Vec<u8> = vec![0; 1024];
        let mut next_time = SteadyTime::now();
        let mut cpu_start = ThreadTime::now();

        loop {
            if self.server.pause.load(Ordering::Relaxed) {
                thread::sleep(::std::time::Duration::from_millis(100));
                continue;
            }

            match self.socket.recv_from(&mut recv_buffer[..]) {
                Ok((length, addr)) => {
                    let swim_payload = match self.server.unwrap_wire(&recv_buffer[0..length]) {
                        Ok(swim_payload) => swim_payload,
                        Err(e) => {
                            // NOTE: In the future, we might want to block people who send us
                            // garbage all the time.
                            error!("Error unwrapping protocol message, {}", e);
                            continue;
                        }
                    };
                    let bytes_received = swim_payload.len();
                    let msg = match Swim::decode(&swim_payload) {
                        Ok(msg) => msg,
                        Err(e) => {
                            // NOTE: In the future, we might want to block people who send us
                            // garbage all the time.
                            error!("Error decoding protocol message, {}", e);
                            continue;
                        }
                    };
                    trace!("SWIM Message: {:?}", msg);
                    match msg.kind {
                        SwimKind::Ping(ping) => {
                            SWIM_BYTES_RECEIVED
                                .with_label_values(&["ping"])
                                .set(bytes_received as f64);
                            if self.server.is_member_blocked(&ping.from.id) {
                                debug!(
                                    "Not processing message from {} - it is blocked",
                                    ping.from.id
                                );
                                continue;
                            }
                            self.process_ping(addr, ping);
                        }
                        SwimKind::Ack(ack) => {
                            SWIM_BYTES_RECEIVED
                                .with_label_values(&["ack"])
                                .set(bytes_received as f64);
                            if self.server.is_member_blocked(&ack.from.id)
                                && ack.forward_to.is_none()
                            {
                                debug!(
                                    "Not processing message from {} - it is blocked",
                                    ack.from.id
                                );
                                continue;
                            }
                            self.process_ack(addr, ack);
                        }
                        SwimKind::PingReq(pingreq) => {
                            SWIM_BYTES_RECEIVED
                                .with_label_values(&["pingreq"])
                                .set(bytes_received as f64);
                            if self.server.is_member_blocked(&pingreq.from.id) {
                                debug!(
                                    "Not processing message from {} - it is blocked",
                                    pingreq.from.id
                                );
                                continue;
                            }
                            self.process_pingreq(addr, pingreq);
                        }
                    }
                }
                Err(e) => {
                    // TODO: We can't use magic numbers here because the Supervisor runs on more
                    // than one platform. I'm sure these were added as specific OS errors for Linux
                    // but we need to also handle Windows & Mac.
                    match e.raw_os_error() {
                        Some(35) | Some(11) | Some(10035) | Some(10060) => {
                            // This is the normal non-blocking result, or a timeout
                            // TODO: I'm not clear why we specifically _want_ a silent failure in
                            // these cases.
                        }
                        Some(_) => {
                            error!("UDP Receive error: {}", e);
                            debug!("UDP Receive error debug: {:?}", e);
                        }
                        None => {
                            error!("UDP Receive error: {}", e);
                        }
                    }
                }
            }

            // JB TODO: this feels like a lot of boilerplate to measure CPU usage. maybe all of
            // this needs to be abstracted into a metrics module
            if SteadyTime::now() >= next_time {
                let current_thread = thread::current();
                let thread_name = current_thread.name().unwrap();
                let cpu_duration = cpu_start.elapsed();
                let cpu_time: f64 = (cpu_duration.as_secs() as f64)
                    + (cpu_duration.subsec_nanos() as f64) / (1_000_000_000 as f64);
                CPU_TIME.with_label_values(&[thread_name]).set(cpu_time);
                next_time = SteadyTime::now() + Duration::seconds(1);
                cpu_start = ThreadTime::now();
            }
        }
    }

    /// Process pingreq messages.
    fn process_pingreq(&self, addr: SocketAddr, mut msg: PingReq) {
        SWIM_MESSAGES_RECEIVED.with_label_values(&["pingreq"]).inc();
        trace_it!(SWIM: &self.server, TraceKind::RecvPingReq, &msg.from.id, addr, &msg);
        msg.from.address = addr.ip().to_string();
        let target = match self
            .server
            .member_list
            .members
            .read()
            .expect("Member list lock poisoned")
            .get(&msg.target.id)
        {
            Some(t) => t.clone(),
            None => {
                error!("PingReq request {:?} for invalid target", msg);
                return;
            }
        };

        // Set the route-back address to the one we received the pingreq from
        outbound::ping(
            &self.server,
            &self.socket,
            &target,
            target.swim_socket_address(),
            Some(msg.from),
        );
    }

    /// Process ack messages; forwards to the outbound thread.
    fn process_ack(&self, addr: SocketAddr, mut msg: Ack) {
        SWIM_MESSAGES_RECEIVED.with_label_values(&["ack"]).inc();
        trace_it!(SWIM: &self.server, TraceKind::RecvAck, &msg.from.id, addr, &msg);
        trace!("Ack from {}@{}", msg.from.id, addr);
        if msg.forward_to.is_some() {
            if *self.server.member_id != msg.forward_to.as_ref().unwrap().id {
                let (forward_to_addr, from_addr) = {
                    let forward_to = msg.forward_to.as_ref().unwrap();
                    let forward_addr_str =
                        format!("{}:{}", forward_to.address, forward_to.swim_port);
                    let forward_to_addr = match forward_addr_str.parse() {
                        Ok(addr) => addr,
                        Err(e) => {
                            error!(
                                "Abandoning Ack forward: cannot parse member address: {}:{}, {}",
                                forward_to.address, forward_to.swim_port, e
                            );
                            return;
                        }
                    };
                    trace!(
                        "Forwarding Ack from {}@{} to {}@{}",
                        msg.from.id,
                        addr,
                        forward_to.id,
                        forward_to.address,
                    );
                    (forward_to_addr, addr.ip().to_string())
                };
                msg.from.address = from_addr;
                outbound::forward_ack(&self.server, &self.socket, forward_to_addr, msg);
                return;
            }
        }
        let memberships = msg.membership.clone();
        match self.tx_outbound.send((addr, msg)) {
            Ok(()) => {
                for membership in memberships {
                    self.server
                        .insert_member_from_rumor(membership.member, membership.health);
                }
            }
            Err(e) => panic!("Outbound thread has died - this shouldn't happen: #{:?}", e),
        }
    }

    /// Process ping messages.
    fn process_ping(&self, addr: SocketAddr, mut msg: Ping) {
        SWIM_MESSAGES_RECEIVED.with_label_values(&["ping"]).inc();
        trace_it!(SWIM: &self.server, TraceKind::RecvPing, &msg.from.id, addr, &msg);
        outbound::ack(&self.server, &self.socket, &msg.from, addr, msg.forward_to);
        // Populate the member for this sender with its remote address
        msg.from.address = addr.ip().to_string();
        trace!("Ping from {}@{}", msg.from.id, addr);
        if msg.from.departed {
            self.server.insert_member(msg.from, Health::Departed);
        } else {
            self.server.insert_member(msg.from, Health::Alive);
        }
        for membership in msg.membership {
            self.server
                .insert_member_from_rumor(membership.member, membership.health);
        }
    }
}
