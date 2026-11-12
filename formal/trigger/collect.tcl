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
    foreach key {name type command disabled validity_status run_status expression precondition clock edge} {
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
    if {$kind eq "cover"} {
        visualize -cover -property $item -batch -silent
    } else {
        visualize -violation -property $item -batch -silent
    }
    visualize -save -vcd $label.vcd
}
proc execute {} {
    global sources top goals expected covers expected_assumptions time_limit scenario
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
    if {$top eq "trigger_formal"} {
        assume -reset {reset && observe_dmode == 0 && observe_debugAction == 0}
    } else {
        assume -reset {reset && systemReset == 0 && dut.csr.trigger.selected == 0 && dut.csr.trigger.dmode == 0 && dut.csr.trigger.dmode_0 == 0 && dut.csr.trigger.hit == 0 && dut.csr.trigger.hit_0 == 0 && dut.csr.trigger.debugAction == 0 && dut.csr.trigger.debugAction_0 == 0 && dut.csr.trigger.machine == 0 && dut.csr.trigger.machine_0 == 0 && dut.csr.trigger.user == 0 && dut.csr.trigger.user_0 == 0 && dut.csr.trigger.execute == 0 && dut.csr.trigger.execute_0 == 0 && dut.csr.trigger.address_0 == 0 && dut.csr.trigger.address_1 == 0 && dut.csr.trigger.mte == 0 && dut.csr.trigger.mpte == 0 && dut.debug.halted == 0 && dut.debug.sending == 0 && dut.debug.waiting == 0 && dut.debug.offered == 0 && dut.debug.dpc == 0 && dut.xValid == 0 && dut.mValid == 0 && dut.architecturalPc == 0 && dut.fetch.assemblyPc == 0 && dut.fetch.nextWord == 0 && dut.fetch.buffered == 0 && dut.fetch.firstValid == 0 && dut.fetch.secondValid == 0 && dut.fetch.outstanding == 0 && dut.fetch.held == 0}
    }
    record setup clock_mode free_running
    set identity [open executable.private w]
    puts $identity [info nameofexecutable]
    close $identity
    scope before
    foreach label $goals {
        set item [property $label]
        metadata before.$label $item
        prove -property [list $item] -time_limit $time_limit
        metadata final.$label $item
        array set info [get_property_info $item]
        if {$info(type) eq "assert" && $info(validity_status) eq "cex" && $expected ne "cex"} {
            trace $label $item cex
        }
        if {$info(type) ne "assert" || $info(command) ne "assert" || $info(disabled) ||
            $info(run_status) ne "processed" || $info(validity_status) ne $expected} {
            error "native goal did not reach its required verdict"
        }
        if {$expected eq "cex"} {trace $label $item cex}
    }
    foreach label $covers {
        set item [property $label]
        prove -property [list $item] -engine_mode B -iter 96 -time_limit $time_limit
        metadata cover.$label $item
        array set info [get_property_info $item]
        if {$info(type) ne "cover" || $info(disabled) ||
            $info(run_status) ne "processed" || $info(validity_status) ne "covered"} {
            error "native cover was not reached"
        }
        trace $label $item cover
    }
    scope after
    record run state complete
}
if {[catch {execute}]} {
    record run state failed
    close $records
    exit 1
}
close $records
exit 0
