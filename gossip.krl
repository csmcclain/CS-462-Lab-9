ruleset gossip {

    meta {
        use module io.picolabs.wrangler alias wrangler
        use module io.picolabs.subscription alias subs
        shares get_events, get_temp_logs, get_smart_tracker, get_threshold_tracker, get_peer_thresold_tracker, get_current_violation, get_threshold
    }

    global {
        get_events = function() {
            schedule:list()
        }
        get_temp_logs = function() {
            ent:temp_logs
        }

        get_smart_tracker = function() {
            ent:smart_tracker
        }

        get_threshold_tracker = function() {
            ent:threshold_tracker
        }

        get_peer_thresold_tracker = function() {
            ent:peer_threshold_tracker
        }

        get_current_violation = function() {
            ent:current_violation
        }

        get_threshold = function() {
            ent:threshold
        }

        generate_rumor_message = function(read_temperature, read_time) {
            {
                "MessageID" : ent:origin_ID + ":" + ent:sequence_num,
                "SensorID": ent:origin_ID,
                "Temperature": read_temperature,
                "Timestamp": read_time
            }
        }

        get_peer_to_send_to = function() {
            // Grab a random peer!
            n = random:integer(lower = 0, upper = ent:peer_to_rx.length() - 1)
            ent:peer_to_rx.keys()[n]
        }

        get_origins_unsent_to_peer = function(peer) {
            peer_data = ent:smart_tracker{peer}
            not_in_peers_map = ent:own_tracker.filter(function(v,k) {
                peer_data{k} == null
            });

            return (not_in_peers_map.length() > 0) => not_in_peers_map.keys()[0] | null
        }

        determine_lartest_defecit = function(peer) {
            peer_data = ent:smart_tracker{peer}
            values_to_update = ent:own_tracker.filter(function(v,k) {
                peer_data{k} < v
            });

            return (values_to_update.length() > 0) => values_to_update.keys()[0] | null
        }

        split_string = function(string_to_split) {
            split_string = string_to_split.split(re#:#)
            split_string[split_string.length() - 1].as("Number")
        }

        get_rumor_message = function(peer, origin_to_send) {
            // Build the message
            last_seen_by_peer = ent:smart_tracker{[peer, origin_to_send]} != null => ent:smart_tracker{[peer, origin_to_send]}.klog("starting at ") | -1.klog("No seen by peer ")
            origin_messages = ent:temp_logs{origin_to_send}
            payload = origin_messages.filter(function(v,k) {
                // K will be the origin_ID:value_to_compare_to
                split_string(k) > last_seen_by_peer
            })
            last_value = split_string(payload.keys()[payload.keys().length() - 1]).klog("LAST VALUE WAS ")


            return {
                "message_type": "rumor",
                "message_payload": payload,
                "message_origin": origin_to_send,
                "peer_sent_to": peer,
                "last_value": last_value
            }
        }

        get_seen_message = function() {
            return {
                "message_type": "seen_message",
                "message_sender": ent:origin_ID,
                "message_payload": ent:own_tracker,
                "message_thresholds": ent:threshold_tracker
            }
        }

        get_state_update_message = function(peer) {
            // First check to see if we have origin data that our peer doesn't have
            unseen_origin_id_by_peer = get_origins_unsent_to_peer(peer).klog("Yoooo")

            // If there were no unsent origins, check if any messages haven't been passed along
            final_rumor_message_check = (unseen_origin_id_by_peer != null) => unseen_origin_id_by_peer | determine_lartest_defecit(peer)

            updates_to_send = (final_rumor_message_check != null) => get_rumor_message(peer, final_rumor_message_check) | get_seen_message()
            updates_to_send
        }

        get_unsent_thresholds_to_send = function(peer) {
            unsent_values = ent:threshold_tracker.filter(function(v,k) {
                // K will be origin:ID V will be what I have
                ent:peer_threshold_tracker{peer}{k} == null
            })
            return_value = (unsent_values == null || unsent_values.keys().length() == 0) => null | unsent_values.keys()[0]
            return_value
        }

        get_threshold_to_send = function(peer) {
            values_to_update = ent:threshold_tracker.filter(function(v,k) {
                // K will be origin:ID V will be what I have
                ent:peer_threshold_tracker{peer}{k} != v && k != peer
            });
            return_value = (values_to_update == null || values_to_update.keys().length() == 0) => null | values_to_update.keys()[0]
            return_value
        }

        get_threshold_message = function(origin_to_update, peer) {
            return {
                "message_type": "threshold_rumor",
                "message_sender": ent:origin_ID,
                "message_payload": {
                    "node_to_update": origin_to_update,
                    "update": ent:threshold_tracker{origin_to_update}
                },
            }
        }

        get_threshold_update_to_send = function(peer) {
            // first check if I have null values
            unseen_threshold_id = get_unsent_thresholds_to_send(peer)

            // Next check if I have mismaches
            final_threshold_message_check = (unseen_threshold_id != null) => unseen_threshold_id | get_threshold_to_send(peer)

            // build and return message
            update_to_send = (final_threshold_message_check != null) => get_threshold_message(final_threshold_message_check) | get_seen_message()
            update_to_send
        }

        get_message_to_send = function(peer) {
            n = random:integer(lower = 0, upper = 1).klog("GOT RANDOM INT ")
            message = (n == 0) => get_state_update_message(peer) | get_threshold_update_to_send(peer)
            message
        }

    }

    // Init related rules
    rule init {
        select when wrangler ruleset_installed

        always {
            ent:n := 5
            ent:origin_ID := wrangler:name()
            ent:sequence_num := 0

            ent:own_tracker := {}
            ent:temp_logs := {}

            ent:smart_tracker := {}
            ent:peer_to_rx := {}
            
            ent:threshold := 75
            ent:threshold_tracker := {}
            ent:threshold_tracker{ent:origin_ID} := 0
            ent:current_violation := false

            ent:peer_threshold_tracker := {}
            
            ent:active_gossip := "on"
        }
    }

    // Heartbeat related rules
    rule start_gossip_beat {
        select when gossip start_beat

        pre {
            n = event:attrs{"beat_time"} == "" =>  ent:n.klog("got n ") | event:attrs{"beat_time"}.klog("got beat ")
        }

        always {
            schedule gossip event "heartbeat" repeat << */#{n} * * * * * >>
        }
    }

    rule stop_gossip_beat {
        select when gossip stop_beat

        pre {
            id = event:attrs{"id"}
        }

        if (id) then schedule:remove(id)
    }

    rule toggel_active {
        select when gossip toggle_beat

        pre {
            active = ent:active_gossip == "on" => "off" | "on"
        }

        always {
            ent:active_gossip := active
        }
    }

    // Peer connection related rules

    rule make_connection_to_peer {
        select when gossip make_connection_to_peer
        pre {
            well_known_rx = event:attrs{"wellKnown_rx"}
        }

        event:send({
            "eci": subs:wellKnown_Rx(){"id"},
            "domain":"wrangler", "name":"subscription",
            "attrs": {
                "wellKnown_Tx": well_known_rx,
                "Rx_role":"node", "Tx_role":"node",
                "channel_type": "subscription",
                "node_name": ent:origin_ID
            }
        })
    }

    rule accept_conection_to_peer {
        select when wrangler inbound_pending_subscription_added
        pre {
            their_origin_id = event:attrs{"node_name"}
            attrs = event:attrs.set("node_name", ent:origin_ID)
            my_role = event:attrs{"Rx_role"}
            their_role = event:attrs{"Tx_role"}
        }
        if my_role=="node" && their_role=="node" then noop()
        fired {
            
            raise wrangler event "pending_subscription_approval"
                attributes attrs
            
            raise gossip event "add_peer" attributes event:attrs
        }
    }

    rule add_peer_to_storage {
        select when gossip add_peer

        pre {
            their_origin_id = event:attrs{"node_name"}
        }

        if (their_origin_id != ent:origin_ID) then noop();

        fired {
            ent:peer_to_rx{their_origin_id} := event:attrs{"Tx"}
            ent:smart_tracker{their_origin_id} := {}
            ent:temp_logs{their_origin_id} := {}
            ent:threshold_tracker{their_origin_id} := 0
            ent:peer_threshold_tracker{their_origin_id} := {}
        }
    }

    rule peer_connection_accepted {
        select when wrangler subscription_added

        pre {
            their_origin_id = event:attrs{"node_name"}
            my_role = event:attrs{"Rx_role"}
            their_role = event:attrs{"Tx_role"}
        }

        if my_role == "node" && their_role == "node" then noop()

        fired {
            raise gossip event "add_peer" attributes event:attrs
        }
    }

    // Create new rumor Message
    rule process_wovyn_reading {
        select when wovyn heartbeat 

        pre {
            genericThing = event:attrs{"genericThing"}.klog("Received genericThing: ")
            time = time:now().klog("Read time at: ")
        } 

        if (genericThing) then noop()

        fired {
            // Generate and save the message
            message = generate_rumor_message(genericThing{"data"}{"temperature"}[0]{"temperatureF"}, time).klog("Got this message ")
            ent:temp_logs{[ent:origin_ID, message{"MessageID"}]} := message

            // Update my own table
            ent:own_tracker{ent:origin_ID} := ent:sequence_num

            // progress the sequence num 
            ent:sequence_num := ent:sequence_num + 1

            raise gossip event "check_threshold" attributes message
        }
    }

    rule process_gossip_heartbeat {
        select when gossip heartbeat where ent:active_gossip == "on"

        pre {
            // Determine which peer to send to
            peer_to_send_to = get_peer_to_send_to().klog("Going to send to peer ")
            rx_to_send_to = ent:peer_to_rx{peer_to_send_to}

            // Determine which message to send
            message_blob = get_message_to_send(peer_to_send_to)
        }

        // Send the message
        event:send({
            "eci": rx_to_send_to,
            "domain": "gossip", "type": message_blob{"message_type"},
            "eid": "gossiping",
            "attrs": message_blob
        });

        // Update my state
        fired {
            raise gossip event "update_state" attributes {
                "peer": peer_to_send_to,
                "update": message_blob
            }
        }
    }

    rule process_state_update {
        select when gossip update_state

        pre {
            peer_sent_to = event:attrs{"peer"}.klog("Sent to peer ")
            message_type = event:attrs{"update"}{"message_type"}.klog("sent message of type ")
            payload = event:attrs{"update"}{"message_payload"}
            origin_id_sent = event:attrs{"update"}{"message_origin"}
            num_sent = event:attrs{"update"}{"last_value"}
        }

        if (message_type == "rumor") then noop()

        fired {
            ent:smart_tracker{[peer_sent_to, origin_id_sent]} := num_sent
        }
    }

    rule process_threshold_state {
        select when gossip update_state
        pre {
            peer = event:attrs{"peer"}.klog("Sent to peer ")
            payload = event:attrs{"update"}{"message_payload"}
            message_type = event:attrs{"update"}{"message_type"}
            node = payload{"node_to_update"}
            update = payload{"update"}
        }

        if (message_type == "threshold_rumor") then noop()

        fired {
            ent:peer_threshold_tracker{[peer, node]} := update
        }
    }

    rule process_rumor {
        select when gossip rumor 

        pre {
            messages = event:attrs{"message_payload"}.klog("Received message ")
            origin = event:attrs{"message_origin"}.klog("Received Origin ")
            num_sent = event:attrs{"last_value"}.klog("Received num sent ")
            logs = ent:temp_logs{origin} == null => {} | ent:temp_logs{origin}
        }

        always {
            // Update my logs
            ent:temp_logs{origin} := logs.put(messages)
            // Update my seen table
            ent:own_tracker{origin} := num_sent
        }
    }

    rule process_seen {
        select when gossip seen_message

        pre {
            origin_id_sent = event:attrs{"message_sender"}
            payload = event:attrs{"message_payload"}
            thresholds = event:attrs{"message_thresholds"}
        }

        always {
            // Update the smart_tracker
            ent:smart_tracker{origin_id_sent} := payload
            ent:peer_threshold_tracker{origin_id_sent} := thresholds
        }
    }

    // new Lab 9 code!

    // Logic to determine if we are in threshold violation

    rule check_threshold {
        select when gossip check_threshold

        pre {
            new_reading = event:attrs{"Temperature"}
        }

        always {
            raise gossip event "new_violation" if (new_reading > ent:threshold && not ent:current_violation)
            raise gossip event "stop_violation" if (new_reading < ent:threshold && ent:current_violation)
            raise gossip event "continue_violation" if (new_reading > ent:threshold && ent:current_violation)
        }
    }

    rule new_violation {
        select when gossip new_violation
        always {
            ent:current_violation := true
            ent:threshold_tracker{ent:origin_ID} := ent:threshold_tracker{ent:origin_ID} + 1
        }
    }

    rule stop_violation {
        select when gossip stop_violation
        always {
            ent:current_violation := false
            ent:threshold_tracker{ent:origin_ID} := ent:threshold_tracker{ent:origin_ID} - 1
        }
    }

    rule continue_violation {
        select when gossip continue_violation
        always {
            ent:current_violation := true
            ent:threshold_tracker{ent:origin_ID} := ent:threshold_tracker{ent:origin_ID} + 0
        }
    }

    // Logic to process threshold gossip 

    rule process_threshold_gossip {
        select when gossip threshold_rumor

        pre {
            real_attrs = event:attrs{"message_payload"}.klog("HEY LOOK YEAH I MADE IT ")
            node = real_attrs{"node_to_update"}
            update = real_attrs{"update"}
        }

        always {
            ent:threshold_tracker{node} := update
        }
    }
}