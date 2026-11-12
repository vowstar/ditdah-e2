# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

source [file join [file dirname [info script]] plan.tcl]
set records [open native.tsv w]
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
proc trace {label item kind} {
    set_trace_optimization standard
    if {$kind eq "cover"} {
        visualize -cover -property $item -batch -silent
    } else {
        visualize -violation -property $item -batch -silent
    }
    visualize -save -vcd $label.vcd
}
proc prove_stage {label prefix bound limit} {
    set item [property $label]
    if {$prefix eq ""} {
        prove -property [list $item] -engine_mode B -iter $bound -time_limit $limit
    } else {
        prove -property [list $item] -from $prefix -engine_mode B -iter $bound -time_limit $limit
    }
    metadata stage.$label $item
    array set info [get_property_info $item]
    if {$info(type) ne "cover" || $info(disabled) ||
        $info(run_status) ne "processed" || $info(validity_status) ne "covered"} {
        error "stage cover was not reached: $label"
    }
    trace $label $item cover
    return $item
}
proc execute {} {
    global sources top goals expected covers expected_assumptions time_limit scenario trace_bound stage_bound stage_time_limit
    if {![info exists trace_bound]} {set trace_bound 256}
    if {![info exists stage_bound]} {set stage_bound 96}
    if {![info exists stage_time_limit]} {set stage_time_limit 180}
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
    assume -reset {reset && systemReset == 0 && dut.csr.mie == 0 && dut.csr.mpie == 0 && dut.csr.interruptEnables == 0 && dut.csr.inhibit == 0 && dut.csr.mtvec == 0 && dut.csr.mscratch == 0 && dut.csr.mepc == 0 && dut.csr.mcause == 0 && dut.csr.mtval == 0 && dut.multiplyDivide.active == 0 && dut.multiplyDivide.valid == 0 && dut.csr.trigger.selected == 0 && dut.csr.trigger.dmode == 0 && dut.csr.trigger.dmode_0 == 0 && dut.csr.trigger.hit == 0 && dut.csr.trigger.hit_0 == 0 && dut.csr.trigger.debugAction == 0 && dut.csr.trigger.debugAction_0 == 0 && dut.csr.trigger.machine == 0 && dut.csr.trigger.machine_0 == 0 && dut.csr.trigger.user == 0 && dut.csr.trigger.user_0 == 0 && dut.csr.trigger.execute == 0 && dut.csr.trigger.execute_0 == 0 && dut.csr.trigger.address_0 == 0 && dut.csr.trigger.address_1 == 0 && dut.csr.trigger.mte == 0 && dut.csr.trigger.mpte == 0 && dut.dm.active == 0 && dut.dm.halt == 0 && dut.dm.resume == 0 && dut.dm.resumeAck == 0 && dut.dm.haltOnReset == 0 && dut.dm.ndmreset == 0 && dut.dm.haveReset == 0 && dut.dm.data0 == 0 && dut.dm.data1 == 0 && dut.dm.error == 0 && dut.dm.busy == 0 && dut.dm.needsHart == 0 && dut.dm.issued == 0 && dut.dm.responding == 0 && dut.debug.halted == 0 && dut.debug.stopping == 0 && dut.debug.stopCause == 0 && dut.debug.step == 0 && dut.debug.stepping == 0 && dut.debug.ebreakMachine == 0 && dut.debug.user == 0 && dut.debug.cause == 0 && dut.debug.resetPending == 0 && dut.debug.resetting == 0 && dut.debug.resetEvent == 0 && dut.debug.resumeAck == 0 && dut.debug.responding == 0 && dut.debug.owner == 0 && dut.debug.sending == 0 && dut.debug.waiting == 0 && dut.debug.offered == 0 && dut.debug.dpc == 0 && dut.xValid == 0 && dut.mValid == 0 && dut.architecturalPc == 0 && dut.fetch.assemblyPc == 0 && dut.fetch.nextWord == 0 && dut.fetch.buffered == 0 && dut.fetch.firstValid == 0 && dut.fetch.secondValid == 0 && dut.fetch.outstanding == 0 && dut.fetch.held == 0 && dut.xInjected == 0 && dut.xSequence == 0 && dut.xTruncated == 0 && dut.sent == 0 && dut.sleeping_0 == 0 && dut.registers == 0 && dut.registers_0 == 0 && dut.registers_1 == 0 && dut.registers_2 == 0 && dut.registers_3 == 0 && dut.registers_4 == 0 && dut.registers_5 == 0 && dut.registers_6 == 0 && dut.registers_7 == 0 && dut.registers_8 == 0 && dut.registers_9 == 0 && dut.registers_10 == 0 && dut.registers_11 == 0 && dut.registers_12 == 0 && dut.registers_13 == 0 && dut.registers_14 == 0 && dut.registers_15 == 0 && dut.registers_16 == 0 && dut.registers_17 == 0 && dut.registers_18 == 0 && dut.registers_19 == 0 && dut.registers_20 == 0 && dut.registers_21 == 0 && dut.registers_22 == 0 && dut.registers_23 == 0 && dut.registers_24 == 0 && dut.registers_25 == 0 && dut.registers_26 == 0 && dut.registers_27 == 0 && dut.registers_28 == 0 && dut.registers_29 == 0 && dut.retirementOrder == 0 && dut.handlerPending == 0 && dut.arithmeticPending == 0 && dut.dm.program0 == 0 && dut.dm.program1 == 0 && dut.dm.commandValid == 0 && dut.dm.auto == 0 && dut.debug.ebreakUser == 0 && dut.debug.injecting == 0 && dut.debug.cancelInjection == 0 && dut.debug.pendingIssue == 0 && dut.debug.slot == 0 && dut.fetch.discarded == 0 && dut.fetch.heldDiscarded == 0 && dut.csr.counters.cycleCount_0 == 0 && dut.csr.counters.instretCount_0 == 0}
    record setup clock_mode free_running
    set identity [open executable.private w]
    puts $identity [info nameofexecutable]
    close $identity
    scope before
    set resume [prove_stage cover_resume_dpc "" 160 $time_limit]
    set prefix $resume
    if {$scenario == 3} {
        set older [prove_stage cover_older_fault_event $prefix $stage_bound $stage_time_limit]
        if {[llength $covers]} {set prefix $older}
        if {[llength $goals] && [lsearch -exact $goals older_fault_blocks_target] >= 0} {set prefix $older}
    } elseif {[llength $covers] && [lindex $covers 0] ne "cover_resume_dpc"} {
        set target [prove_stage cover_target_breakpoint $prefix $stage_bound $stage_time_limit]
        set epc [prove_stage cover_native_epc $target $stage_bound $stage_time_limit]
        set cause [prove_stage cover_native_cause $epc $stage_bound $stage_time_limit]
        set tval [prove_stage cover_native_tval $cause $stage_bound $stage_time_limit]
        set control [prove_stage cover_native_control $tval $stage_bound $stage_time_limit]
        set hit [prove_stage cover_native_hit $control $stage_bound $stage_time_limit]
        set prefix $hit
        if {$scenario == 1} {
            set prefix [prove_stage cover_multiply_start $prefix $stage_bound $stage_time_limit]
            set prefix [prove_stage cover_multiply_done $prefix $stage_bound $stage_time_limit]
        }
        if {$scenario <= 1} {set prefix [prove_stage cover_target_normal $prefix $stage_bound $stage_time_limit]}
        if {$scenario == 1} {set prefix [prove_stage cover_multiply_value $prefix $stage_bound $stage_time_limit]}
        set prefix [prove_stage cover_completion $prefix $stage_bound $stage_time_limit]
    }
    foreach label $goals {
        set item [property $label]
        metadata before.$label $item
        prove -property [list $item] -from $prefix -engine_mode B -iter $trace_bound -time_limit $time_limit
        metadata final.$label $item
        array set info [get_property_info $item]
        if {$info(type) ne "assert" || $info(command) ne "assert" || $info(disabled) ||
            $info(run_status) ne "processed" || $info(validity_status) ne "cex"} {
            error "negative control did not produce a counterexample"
        }
        trace $label $item cex
    }
    foreach label $covers {
        if {$label eq "cover_resume_dpc"} {
            set item $resume
        } else {
            set item [property $label]
            if {$label in {cover_cold_reset cover_first_dmi}} {
                prove -property [list $item] -engine_mode B -iter $stage_bound -time_limit $stage_time_limit
            } else {
                prove -property [list $item] -from $prefix -engine_mode B -iter $stage_bound -time_limit $time_limit
            }
        }
        metadata cover.$label $item
        array set info [get_property_info $item]
        if {$info(type) ne "cover" || $info(disabled) ||
            $info(run_status) ne "processed" || $info(validity_status) ne "covered"} {
            error "native cover was not reached"
        }
        if {$label ne "cover_resume_dpc"} {trace $label $item cover}
    }
    save -jdb proof.jdb
    scope after
    record run state complete
}
if {[catch {execute} error]} {
    record run state failed
    record run error $error
    close $records
    exit 1
}
close $records
exit 0
