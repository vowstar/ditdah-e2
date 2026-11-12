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
    set found {}
    foreach item [get_property_list] {
        if {[string match "*.$label" $item]} {lappend found $item}
    }
    if {[llength $found] != 1} {error "missing or ambiguous property"}
    return [lindex $found 0]
}
proc metadata {tag item} {
    array set info [get_property_info $item]
    foreach key {name type command disabled validity_status run_status expression precondition clock edge engine min_length max_length target_bound trace_length latest_trace_engine} {
        if {[info exists info($key)]} {record $tag $key $info($key)}
    }
}
proc scope {tag} {
    global expected_assumptions top
    record $tag clock [clock -list configuration -silent]
    record $tag reset [reset -list -typed_list -silent]
    record $tag global [assume -list -silent -env]
    set reset_initial [assume -reset -list -silent]
    record $tag reset_initial $reset_initial
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
proc trace {label item} {
    set_trace_optimization standard
    visualize -violation -property $item -batch -silent
    visualize -save -vcd $label.vcd
}
proc prove_group {labels bound engines jobs limit per_property_limit {first_attempt 1}} {
    global group_serial bounds proof_round before_recorded goals
    incr group_serial
    record group.$group_serial labels $labels
    record group.$group_serial round $proof_round
    record group.$group_serial bound $bound
    record group.$group_serial engines $engines
    record group.$group_serial per_engine_max_jobs $jobs
    record group.$group_serial time_limit $limit
    record group.$group_serial per_property_time_limit $per_property_limit
    record group.$group_serial first_trace_attempt $first_attempt
    set items {}
    set pending {}
    foreach label $labels {
        set item [property $label]
        if {![info exists before_recorded($label)]} {
            metadata before.$label $item
            set before_recorded($label) 1
        }
        metadata attempt.$proof_round.before.$label $item
        array set existing [get_property_info $item]
        if {$existing(validity_status) eq "proven"} {
            metadata attempt.$proof_round.after.$label $item
        } else {
            lappend items $item
            lappend pending $label
        }
    }
    if {$proof_round > 1} {
        set facts {}
        foreach label $goals {
            set item [property $label]
            array unset fact
            array set fact [get_property_info $item]
            if {$fact(validity_status) eq "proven" && $fact(min_length) eq "infinite" && $fact(target_bound) == 0} {
                lappend facts $label
                metadata lemma.$group_serial.$label $item
            } elseif {$fact(validity_status) ni {unknown undetermined cex}} {
                error "unsupported proof state before retry: $label"
            }
        }
        record group.$group_serial unbounded_facts $facts
    }
    if {![llength $items]} {return}
    if {$bound == 0} {
        prove -property $items -with_proven -engine_mode $engines -time_limit $limit \
            -per_property_time_limit $per_property_limit -per_engine_max_jobs $jobs
    } else {
        prove -property $items -with_proven -engine_mode $engines -iter $bound -time_limit $limit \
            -per_property_time_limit $per_property_limit -per_engine_max_jobs $jobs -first_trace_attempt $first_attempt
    }
    set failures {}
    foreach label $pending {
        set item [property $label]
        metadata attempt.$proof_round.after.$label $item
        array set info [get_property_info $item]
        if {$info(validity_status) eq "cex"} {
            trace $label $item
            lappend failures $label
            continue
        }
        set required_bound $bound
        if {[info exists bounds($label)]} {set required_bound $bounds($label)}
        set bounded [expr {$required_bound > 0 && $info(validity_status) eq "undetermined" &&
            $info(min_length) ne "infinite" && $info(min_length) >= $required_bound}]
        if {$info(type) ne "assert" || $info(command) ne "assert" || $info(disabled) ||
            $info(run_status) ne "processed" || ($info(validity_status) ne "proven" && !$bounded)} {
            lappend failures $label
        }
    }
    record group.$group_serial unresolved $failures
}
proc attempt_group {args} {
    global group_failures group_serial
    if {[catch {prove_group {*}$args} error]} {
        lappend group_failures $error
        record group.$group_serial failure $error
    }
}
proc execute {} {
    global sources top goals expected_assumptions time_limit scenario trace_bound proof_seed group_serial bounds
    global group_failures scope_after_attempted proof_groups retry_groups proof_round before_recorded
    if {![info exists trace_bound]} {set trace_bound 288}
    analyze -sv12 {*}$sources
    set parameters {}
    if {[info exists scenario]} {lappend parameters -parameter SCENARIO $scenario}
    elaborate -top $top {*}$parameters -disable_auto_bbox -global_embedded_assumes
    foreach key {bbox_inst bbox_mod bbox_out stopat} {
        set values [get_design_info -list $key]
        record setup $key [llength $values]
        if {[llength $values]} {error "nonzero blackbox or stopat"}
    }
    clock -none
    reset -expression reset
    assume -reset {reset && systemReset == 0 && dut.csr.mie == 0 && dut.csr.mpie == 0 && dut.csr.interruptEnables == 0 && dut.csr.inhibit == 0 && dut.csr.mtvec == 0 && dut.csr.mscratch == 0 && dut.csr.mepc == 0 && dut.csr.mcause == 0 && dut.csr.mtval == 0 && dut.multiplyDivide.active == 0 && dut.multiplyDivide.valid == 0 && dut.csr.trigger.selected == 0 && dut.csr.trigger.dmode == 0 && dut.csr.trigger.dmode_0 == 0 && dut.csr.trigger.hit == 0 && dut.csr.trigger.hit_0 == 0 && dut.csr.trigger.debugAction == 0 && dut.csr.trigger.debugAction_0 == 0 && dut.csr.trigger.machine == 0 && dut.csr.trigger.machine_0 == 0 && dut.csr.trigger.user == 0 && dut.csr.trigger.user_0 == 0 && dut.csr.trigger.execute == 0 && dut.csr.trigger.execute_0 == 0 && dut.csr.trigger.address_0 == 0 && dut.csr.trigger.address_1 == 0 && dut.csr.trigger.mte == 0 && dut.csr.trigger.mpte == 0 && dut.dm.active == 0 && dut.dm.halt == 0 && dut.dm.resume == 0 && dut.dm.resumeAck == 0 && dut.dm.haltOnReset == 0 && dut.dm.ndmreset == 0 && dut.dm.haveReset == 0 && dut.dm.data0 == 0 && dut.dm.data1 == 0 && dut.dm.error == 0 && dut.dm.busy == 0 && dut.dm.needsHart == 0 && dut.dm.issued == 0 && dut.dm.responding == 0 && dut.debug.halted == 0 && dut.debug.stopping == 0 && dut.debug.stopCause == 0 && dut.debug.step == 0 && dut.debug.stepping == 0 && dut.debug.ebreakMachine == 0 && dut.debug.user == 0 && dut.debug.cause == 0 && dut.debug.resetPending == 0 && dut.debug.resetting == 0 && dut.debug.resetEvent == 0 && dut.debug.resumeAck == 0 && dut.debug.responding == 0 && dut.debug.owner == 0 && dut.debug.sending == 0 && dut.debug.waiting == 0 && dut.debug.offered == 0 && dut.debug.dpc == 0 && dut.xValid == 0 && dut.mValid == 0 && dut.architecturalPc == 0 && dut.fetch.assemblyPc == 0 && dut.fetch.nextWord == 0 && dut.fetch.buffered == 0 && dut.fetch.firstValid == 0 && dut.fetch.secondValid == 0 && dut.fetch.outstanding == 0 && dut.fetch.held == 0 && dut.sent == 0 && dut.sleeping_0 == 0 && dut.registers == 0 && dut.registers_0 == 0 && dut.registers_1 == 0 && dut.registers_2 == 0 && dut.registers_3 == 0 && dut.registers_4 == 0 && dut.registers_5 == 0 && dut.registers_6 == 0 && dut.registers_7 == 0 && dut.registers_8 == 0 && dut.registers_9 == 0 && dut.registers_10 == 0 && dut.registers_11 == 0 && dut.registers_12 == 0 && dut.registers_13 == 0 && dut.registers_14 == 0 && dut.registers_15 == 0 && dut.registers_16 == 0 && dut.registers_17 == 0 && dut.registers_18 == 0 && dut.registers_19 == 0 && dut.registers_20 == 0 && dut.registers_21 == 0 && dut.registers_22 == 0 && dut.registers_23 == 0 && dut.registers_24 == 0 && dut.registers_25 == 0 && dut.registers_26 == 0 && dut.registers_27 == 0 && dut.registers_28 == 0 && dut.registers_29 == 0 && dut.retirementOrder == 0 && dut.handlerPending == 0 && dut.arithmeticPending == 0 && dut.dm.commandValid == 0 && dut.dm.auto == 0 && dut.fetch.discarded == 0 && dut.fetch.heldDiscarded == 0 && dut.csr.counters.cycleCount_0 == 0 && dut.csr.counters.instretCount_0 == 0}
    record setup clock_mode free_running
    set identity [open executable.private w]
    puts $identity [info nameofexecutable]
    close $identity
    scope before
    if {[info exists proof_seed]} {restore -jdb $proof_seed}
    set ordered {abstract_dpc_value resume_pc_matches initial_dpc_zero no_external_event target_first_event_is_breakpoint older_fault_cause older_load_retires_first no_store_before_breakpoint older_fault_blocks_store older_fault_blocks_target no_multiply_before_breakpoint multiply_has_target_identity target_retry_has_no_trap target_has_no_writeback_on_trap target_single_retry illegal_single_breakpoint native_epc_metadata native_cause_metadata native_tval_metadata native_control_metadata native_hit_metadata}
    array set bounds {}
    foreach label $ordered {set bounds($label) $trace_bound}
    set bounds(initial_dpc_zero) 0
    foreach label {abstract_dpc_value resume_pc_matches} {
        set bounds($label) [expr {$scenario == 0 ? 112 : 128}]
    }
    set bounds(target_first_event_is_breakpoint) [expr {$scenario == 1 ? 160 : 128}]
    foreach label {no_store_before_breakpoint no_multiply_before_breakpoint} {
        if {$scenario != 1} {set bounds($label) 128}
    }
    if {$scenario == 1} {
        foreach label {native_epc_metadata native_cause_metadata} {set bounds($label) 176}
        set bounds(native_tval_metadata) 192
        foreach label {native_control_metadata native_hit_metadata} {set bounds($label) 208}
    } else {
        foreach label {native_epc_metadata native_cause_metadata} {set bounds($label) 160}
        set bounds(native_tval_metadata) 176
        foreach label {native_control_metadata native_hit_metadata} {set bounds($label) 192}
    }
    set group_serial 0
    set group_failures {}
    set proof_round 1
    array set before_recorded {}
    foreach group $proof_groups {
        array unset configuration
        array set configuration $group
        attempt_group $configuration(labels) $configuration(bound) $configuration(engines) \
            $configuration(per_engine_max_jobs) $configuration(time_limit) \
            $configuration(per_property_time_limit) $configuration(first_trace_attempt)
    }
    set proof_round 2
    set selected {}
    foreach group $retry_groups {
        array unset configuration
        array set configuration $group
        set label [lindex $configuration(labels) 0]
        set item [property $label]
        metadata retry.candidate.$label $item
        array unset candidate
        array set candidate [get_property_info $item]
        if {$candidate(validity_status) eq "undetermined" &&
            $candidate(min_length) ne "infinite" && $candidate(min_length) < $bounds($label)} {
            lappend selected $label
            attempt_group $configuration(labels) $configuration(bound) $configuration(engines) \
                $configuration(per_engine_max_jobs) $configuration(time_limit) \
                $configuration(per_property_time_limit) $configuration(first_trace_attempt)
        }
    }
    record retry selected_labels $selected
    set final_failures {}
    foreach label $goals {
        set item [property $label]
        metadata final.$label $item
        array unset info
        array set info [get_property_info $item]
        set required_bound $bounds($label)
        if {$required_bound > 0 && $info(validity_status) eq "undetermined" &&
            $info(min_length) ne "infinite" && $info(min_length) >= $required_bound} {
            assert -set_target_bound $required_bound $item
            metadata bounded.$label $item
            array set info [get_property_info $item]
        }
        if {$info(validity_status) ni {proven bounded_proven_user} || $info(type) ne "assert" ||
            $info(command) ne "assert" || $info(disabled) || $info(run_status) ne "processed"} {
            lappend final_failures $label
        }
    }
    save -jdb proof.jdb
    set scope_after_attempted 1
    scope after
    if {[llength $group_failures]} {error "native proof groups failed: [join $group_failures {; }]"}
    if {[llength $final_failures]} {error "native goals did not reach their required verdicts: [join $final_failures ,]"}
    record run state complete
}
if {[catch {execute} error]} {
    if {!$scope_after_attempted} {
        set scope_after_attempted 1
        if {[catch {scope after} scope_error]} {record run scope_error $scope_error}
    }
    record run state failed
    record run error $error
    close $records
    exit 1
}
close $records
exit 0
