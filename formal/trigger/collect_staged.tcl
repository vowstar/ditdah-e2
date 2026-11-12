# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

source [file join [file dirname [info script]] plan.tcl]
set records [open native.tsv w]
set scope_after_attempted 0
proc record {group name value} {
    global records
    set fields {}
    foreach field [list $group $name $value] {
        lappend fields [binary encode hex [encoding convertto utf-8 $field]]
    }
    puts $records [join $fields "\t"]
    flush $records
}
proc property {label} {
    global top
    set expected "${top}.$label"
    set found {}
    foreach item [get_property_list] {
        if {$item in [list $expected "<embedded>::$expected"]} {lappend found $item}
    }
    if {[llength $found] != 1} {error "missing or ambiguous exact native property"}
    return [lindex $found 0]
}
proc metadata {tag item} {
    record $tag native_id $item
    array set info [get_property_info $item]
    foreach key {name type command disabled validity_status run_status expression precondition clock edge engine min_length max_length target_bound trace_length latest_trace_engine} {
        if {[info exists info($key)]} {record $tag $key $info($key)}
    }
    return [array get info]
}
proc scope {tag} {
    global expected_assumptions top cold_expression_sha256
    record $tag clock [clock -list configuration -silent]
    record $tag reset [reset -list -typed_list -silent]
    record $tag global [assume -list -silent -env]
    set reset_initial [assume -reset -list -silent]
    record $tag reset_initial $reset_initial
    record $tag declared_cold_expression_sha256 $cold_expression_sha256
    if {$reset_initial ne "assume:0"} {error "unexpected reset_initial metadata"}
    set enabled {}
    set initial_found 0
    set initial_name "${top}.initial_common_cold_reset"
    foreach item [get_property_list] {
        array unset info
        array set info [get_property_info $item]
        if {$info(type) eq "assume"} {
            if {$info(disabled) || $info(command) ne "assume"} {error "disabled assumption"}
            if {$info(name) eq $initial_name} {
                set initial_found 1
            } else {
                lappend enabled $info(name)
            }
        }
    }
    if {!$initial_found} {error "missing initial cold reset assumption"}
    record $tag initial_common_cold_reset $initial_found
    record $tag assumptions [lsort $enabled]
    if {[lsort $enabled] ne [lsort $expected_assumptions]} {error "unexpected assumption set"}
}
set exported_witnesses {}
proc trace {label item} {
    global exported_witnesses
    if {[dict exists $exported_witnesses $item]} {
        if {[dict get $exported_witnesses $item] ne $label} {error "native witness identity changed"}
        return
    }
    set destination "$label.vcd"
    if {[file exists $destination]} {error "native witness path already exists: $destination"}
    set_trace_optimization standard
    visualize -violation -property $item -batch -silent
    visualize -save -vcd $destination
    if {![file isfile $destination]} {error "native witness export did not create a file"}
    dict set exported_witnesses $item $label
}

set final_written 0
proc assertion {label} {
    global all_assertions top response_goal
    if {$label ni $all_assertions} {error "unexpected assertion"}
    set item [property $label]
    array set info [get_property_info $item]
    foreach {key value} [list name "${top}.$label" type assert command assert disabled 0 expression $label precondition 0] {
        if {![info exists info($key)] || $info($key) ne $value} {error "assertion identity differs"}
    }
    if {$label eq $response_goal} {
        if {[info exists info(clock)] || [info exists info(edge)]} {error "global response clock metadata differs"}
    } else {
        foreach {key expected} {clock clock edge posedge} {
            if {[info exists info($key)] && $info($key) ni [list "" $expected]} {error "posedge assertion clock differs"}
        }
    }
    return $item
}
proc unbounded {item} {
    array set info [get_property_info $item]
    if {$info(validity_status) ne "proven"} {return 0}
    foreach {key value} {run_status processed min_length infinite max_length infinite target_bound 0} {
        if {![info exists info($key)] || $info($key) ne $value} {error "finite result cannot be unbounded"}
    }
    if {![info exists info(engine)] || $info(engine) ni {PRE N C I Mp Hp B}} {error "infinite result has an unsupported native engine identity"}
    return 1
}
proc final_metadata {} {
    global all_assertions final_written
    if {$final_written} {return}
    set final_written 1
    foreach label $all_assertions {metadata final.$label [assertion $label]}
}
proc snapshot {tag} {
    global all_assertions state_snapshots
    foreach label $all_assertions {
        set item [assertion $label]
        set info [metadata $tag.$label $item]
        lappend info native_id $item
        set state_snapshots($tag,$label) $info
    }
}
proc info_infinite {values} {
    array set info $values
    if {$info(validity_status) ne "proven"} {return 0}
    foreach {key value} {run_status processed min_length infinite max_length infinite target_bound 0} {
        if {![info exists info($key)] || $info($key) ne $value} {error "finite result cannot be an infinite fact"}
    }
    if {![info exists info(engine)] || $info(engine) ni {PRE N C I Mp Hp B}} {error "infinite result has an unsupported native engine identity"}
    return 1
}
proc info_qualified {values bound} {
    array set info $values
    if {[info_infinite $values]} {return 1}
    return [expr {$bound > 0 && $info(validity_status) eq "undetermined" && $info(run_status) eq "processed" &&
        $info(target_bound) eq "0" && [string is integer -strict $info(min_length)] && $info(min_length) >= $bound}]
}
proc check_raw {tag} {
    global all_assertions state_snapshots fatal_errors
    foreach label $all_assertions {
        array unset info
        array set info $state_snapshots($tag,$label)
        foreach key {validity_status run_status engine min_length max_length target_bound trace_length latest_trace_engine} {
            if {![info exists info($key)] || $info($key) eq ""} {lappend fatal_errors "${tag}: missing proof metadata $label $key"}
        }
        if {$info(validity_status) eq "cex"} {
            lappend fatal_errors "${tag}: counterexample $label"
            if {[catch {trace $label $info(native_id)} why]} {
                lappend fatal_errors "${tag}: witness export failed $label: $why"
            }
        }
        if {$info(validity_status) in {bounded_proven bounded_proven_user} || $info(target_bound) ne "0"} {
            lappend fatal_errors "${tag}: unexpected finite proof state $label"
        }
        if {[catch {info_infinite $state_snapshots($tag,$label)} why]} {lappend fatal_errors $why}
    }
}
proc query {tag labels limit guard engines jobs iteration_cap first_trace execute reason snapshot_tag} {
    global state_snapshots fatal_errors executed_queries allocated_search_seconds
    set items {}
    set names {}
    foreach label $labels {
        array unset info
        array set info $state_snapshots($snapshot_tag,$label)
        lappend items $info(native_id)
        lappend names $info(name)
    }
    set import_before [get_prove_invariants_import]
    set orchestration_before [get_prove_orchestration]
    if {$execute && $import_before ne "on"} {
        set execute 0
        set reason unsafe_import_setting
        lappend fatal_errors "${tag}: invariant import was disabled"
    }
    foreach {key value} [list labels $labels actual_properties $items canonical_properties $names engines $engines \
        time_limit $limit per_property_time_limit $guard per_engine_max_jobs $jobs iteration_cap $iteration_cap first_trace_attempt $first_trace \
        uses_proven_directives 1 invariant_import on executed $execute skip_reason $reason] {record $tag $key $value}
    record $tag import_before $import_before
    record $tag orchestration_before $orchestration_before
    if {$execute} {
        incr executed_queries
        incr allocated_search_seconds $limit
        record $tag allocated_seconds $limit
        if {$engines eq "B"} {
            set failed [catch {prove -property $items -with_proven -engine_mode B -iter $iteration_cap -first_trace_attempt $first_trace \
                -time_limit $limit -per_property_time_limit $guard -per_engine_max_jobs $jobs} message]
        } else {
            set failed [catch {prove -property $items -with_proven -engine_mode $engines -time_limit $limit \
                -per_property_time_limit $guard -per_engine_max_jobs $jobs} message]
        }
        if {$failed} {record $tag tool_error $message;lappend fatal_errors "${tag}: native command failed"}
    } else {
        record $tag allocated_seconds 0
    }
    snapshot $tag.after
    scope $tag.after_scope
    set imported [get_prove_invariants_import]
    set orchestrated [get_prove_orchestration]
    record $tag import_after $imported
    record $tag orchestration_after $orchestrated
    if {$imported ne "on" || $orchestrated ne $orchestration_before} {lappend fatal_errors "${tag}: proof settings changed"}
    check_raw $tag.after
}
proc execute {} {
    global sources top scenario original_goals all_assertions query_goals original_bounds scope_after_attempted query_schedule
    global state_snapshots fatal_errors executed_queries allocated_search_seconds proof_queries_finished
    set fatal_errors {}
    set executed_queries 0
    set allocated_search_seconds 0
    set proof_queries_finished 0
    analyze -sv12 {*}$sources
    elaborate -top $top -parameter SCENARIO $scenario -disable_auto_bbox -global_embedded_assumes
    foreach key {bbox_inst bbox_mod bbox_out stopat} {
        set values [get_design_info -list $key]
        record setup $key [llength $values]
        if {[llength $values]} {error "nonzero blackbox or stopat"}
    }
    clock -none
    reset -expression reset
    assume -reset {reset && systemReset == 0 && dut.csr.mie == 0 && dut.csr.mpie == 0 && dut.csr.interruptEnables == 0 && dut.csr.inhibit == 0 && dut.csr.mtvec == 0 && dut.csr.mscratch == 0 && dut.csr.mepc == 0 && dut.csr.mcause == 0 && dut.csr.mtval == 0 && dut.multiplyDivide.active == 0 && dut.multiplyDivide.valid == 0 && dut.csr.trigger.selected == 0 && dut.csr.trigger.dmode == 0 && dut.csr.trigger.dmode_0 == 0 && dut.csr.trigger.hit == 0 && dut.csr.trigger.hit_0 == 0 && dut.csr.trigger.debugAction == 0 && dut.csr.trigger.debugAction_0 == 0 && dut.csr.trigger.machine == 0 && dut.csr.trigger.machine_0 == 0 && dut.csr.trigger.user == 0 && dut.csr.trigger.user_0 == 0 && dut.csr.trigger.execute == 0 && dut.csr.trigger.execute_0 == 0 && dut.csr.trigger.address_0 == 0 && dut.csr.trigger.address_1 == 0 && dut.csr.trigger.mte == 0 && dut.csr.trigger.mpte == 0 && dut.dm.active == 0 && dut.dm.halt == 0 && dut.dm.resume == 0 && dut.dm.resumeAck == 0 && dut.dm.haltOnReset == 0 && dut.dm.ndmreset == 0 && dut.dm.haveReset == 0 && dut.dm.data0 == 0 && dut.dm.data1 == 0 && dut.dm.error == 0 && dut.dm.busy == 0 && dut.dm.needsHart == 0 && dut.dm.issued == 0 && dut.dm.responding == 0 && dut.debug.halted == 0 && dut.debug.stopping == 0 && dut.debug.stopCause == 0 && dut.debug.step == 0 && dut.debug.stepping == 0 && dut.debug.ebreakMachine == 0 && dut.debug.user == 0 && dut.debug.cause == 0 && dut.debug.resetPending == 0 && dut.debug.resetting == 0 && dut.debug.resetEvent == 0 && dut.debug.resumeAck == 0 && dut.debug.responding == 0 && dut.debug.owner == 0 && dut.debug.sending == 0 && dut.debug.waiting == 0 && dut.debug.offered == 0 && dut.debug.dpc == 0 && dut.xValid == 0 && dut.mValid == 0 && dut.architecturalPc == 0 && dut.fetch.assemblyPc == 0 && dut.fetch.nextWord == 0 && dut.fetch.buffered == 0 && dut.fetch.firstValid == 0 && dut.fetch.secondValid == 0 && dut.fetch.outstanding == 0 && dut.fetch.held == 0 && dut.xInjected == 0 && dut.xSequence == 0 && dut.xTruncated == 0 && dut.sent == 0 && dut.sleeping_0 == 0 && dut.registers == 0 && dut.registers_0 == 0 && dut.registers_1 == 0 && dut.registers_2 == 0 && dut.registers_3 == 0 && dut.registers_4 == 0 && dut.registers_5 == 0 && dut.registers_6 == 0 && dut.registers_7 == 0 && dut.registers_8 == 0 && dut.registers_9 == 0 && dut.registers_10 == 0 && dut.registers_11 == 0 && dut.registers_12 == 0 && dut.registers_13 == 0 && dut.registers_14 == 0 && dut.registers_15 == 0 && dut.registers_16 == 0 && dut.registers_17 == 0 && dut.registers_18 == 0 && dut.registers_19 == 0 && dut.registers_20 == 0 && dut.registers_21 == 0 && dut.registers_22 == 0 && dut.registers_23 == 0 && dut.registers_24 == 0 && dut.registers_25 == 0 && dut.registers_26 == 0 && dut.registers_27 == 0 && dut.registers_28 == 0 && dut.registers_29 == 0 && dut.retirementOrder == 0 && dut.handlerPending == 0 && dut.arithmeticPending == 0 && dut.dm.program0 == 0 && dut.dm.program1 == 0 && dut.dm.commandValid == 0 && dut.dm.auto == 0 && dut.debug.ebreakUser == 0 && dut.debug.injecting == 0 && dut.debug.cancelInjection == 0 && dut.debug.pendingIssue == 0 && dut.debug.slot == 0 && dut.fetch.discarded == 0 && dut.fetch.heldDiscarded == 0 && dut.csr.counters.cycleCount_0 == 0 && dut.csr.counters.instretCount_0 == 0 && core_geom_sync_epoch == 1}
    record setup clock_mode free_running
    record setup dut_cold_facts 122
    record setup observer_cold_facts 1
    record setup target_search_bound 0
    record setup maximum_search_budget_seconds 840
    set identity [open executable.private w]
    puts $identity [info nameofexecutable]
    close $identity
    scope before
    set native_assertions {}
    foreach item [get_property_list] {
        array unset info
        array set info [get_property_info $item]
        if {$info(type) eq "assert"} {lappend native_assertions $info(name)}
    }
    set expected {}
    foreach label $all_assertions {lappend expected "${top}.$label"}
    if {[lsort $native_assertions] ne [lsort $expected]} {error "assertion inventory differs"}
    record setup native_assertions $native_assertions
    snapshot before
    check_raw before
    if {[llength $fatal_errors]} {error "invalid fresh proof state"}
    record settings before_invariants_import [get_prove_invariants_import]
    set orchestration_before [get_prove_orchestration]
    record settings before_orchestration $orchestration_before
    set_prove_invariants_import on
    set imported [get_prove_invariants_import]
    record settings active_invariants_import $imported
    if {$imported ne "on"} {error "invariant import was not enabled"}

    foreach entry $query_schedule {
        lassign $entry tag kind fixed limit guard engines jobs
        set current_assertions {}
        foreach item [get_property_list] {
            array unset info
            array set info [get_property_info $item]
            if {$info(type) eq "assert"} {lappend current_assertions $info(name)}
        }
        if {[lsort $current_assertions] ne [lsort $expected]} {error "fresh assertion inventory differs"}
        record $tag native_assertions $current_assertions
        record $tag kind $kind
        snapshot $tag.before
        scope $tag.before_scope
        check_raw $tag.before
        set facts {}
        set fact_items {}
        set fact_names {}
        foreach label $all_assertions {
            set is_infinite 0
            if {[catch {info_infinite $state_snapshots($tag.before,$label)} is_infinite]} {
                lappend fatal_errors "${tag}: invalid fact state $label"
                set is_infinite 0
            }
            if {$is_infinite} {
                array unset info
                array set info $state_snapshots($tag.before,$label)
                lappend facts $label
                lappend fact_items $info(native_id)
                lappend fact_names $info(name)
            }
        }
        record $tag fact_labels $facts
        record $tag fact_actual_properties $fact_items
        record $tag fact_canonical_properties $fact_names
        set selected $fixed
        if {$kind eq "remaining"} {
            set selected {}
            foreach label $original_goals {
                set accepted 0
                if {[catch {info_qualified $state_snapshots($tag.before,$label) $original_bounds($label)} accepted]} {set accepted 0}
                if {!$accepted} {lappend selected $label}
            }
        }
        set run_query [expr {[llength $selected] > 0 && [llength $fatal_errors] == 0}]
        set iteration_cap none
        set first_trace none
        if {$kind eq "remaining"} {
            set iteration_cap 1
            set first_trace 1
            foreach label $selected {
                if {$original_bounds($label) > $iteration_cap} {set iteration_cap $original_bounds($label)}
            }
        }
        set reason {}
        if {[llength $fatal_errors]} {set reason prior_query_failed} elseif {![llength $selected]} {set reason no_pending_originals}
        query $tag $selected $limit $guard $engines $jobs $iteration_cap $first_trace $run_query $reason $tag.before
    }
    record run scheduled_queries [llength $query_schedule]

    set proof_queries_finished 1
    record run proof_queries_finished $proof_queries_finished
    final_metadata
    set incomplete {}
    set converted {}
    foreach label $original_goals {
        set item [property $label]
        array unset info
        array set info [get_property_info $item]
        set bound $original_bounds($label)
        if {$bound > 0 && $info(validity_status) eq "undetermined" && $info(run_status) eq "processed" &&
            [string is integer -strict $info(min_length)] && $info(min_length) >= $bound && $info(target_bound) eq "0"} {
            array unset raw
            array set raw [array get info]
            if {[catch {assert -set_target_bound $bound $item} why]} {
                record bounded.$label tool_error $why
                lappend fatal_errors "bounded conversion failed $label"
            } else {
                metadata bounded.$label $item
                lappend converted $label
                array unset info
                array set info [get_property_info $item]
                foreach key {engine min_length max_length trace_length latest_trace_engine} {
                    if {![info exists info($key)] || $info($key) ne $raw($key)} {
                        lappend fatal_errors "bounded conversion changed raw proof metadata $label $key"
                    }
                }
            }
        }
        set accepted 0
        if {$info(validity_status) eq "proven"} {
            if {[catch {unbounded $item} accepted]} {set accepted 0}
        } elseif {$bound > 0 && $info(validity_status) eq "bounded_proven_user" && $info(run_status) eq "processed" &&
            $info(target_bound) == $bound && [string is integer -strict $info(min_length)] && $info(min_length) >= $bound} {
            set accepted 1
        }
        if {!$accepted} {lappend incomplete $label}
    }
    set import_after [get_prove_invariants_import]
    set orchestration_after [get_prove_orchestration]
    record settings after_invariants_import $import_after
    record settings after_orchestration $orchestration_after
    if {$import_after ne "on" || $orchestration_after ne $orchestration_before} {lappend fatal_errors "proof settings changed"}
    set scope_after_attempted 1
    scope after
    record run converted $converted
    record run incomplete $incomplete
    record run fatal_errors $fatal_errors
    record run executed_queries $executed_queries
    record run allocated_search_seconds $allocated_search_seconds
    if {[llength $incomplete] || [llength $fatal_errors]} {error "staged original-property proof incomplete"}
    record run state complete
}
if {[catch {execute} message]} {
    catch {final_metadata}
    if {!$scope_after_attempted} {
        set scope_after_attempted 1
        if {[catch {scope after} why]} {record run scope_error $why}
    }
    record run state failed
    record run error $message
    close $records
    exit 1
}
close $records
exit 0
