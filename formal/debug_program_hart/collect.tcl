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
    record $tag reset_assumptions [assume -reset -list -silent]
    set enabled {}
    set initial_found 0
    set initial_name "initial_common_cold_reset"
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
proc execute {} {
    global sources top goals expected covers expected_assumptions time_limit
    analyze -sv12 {*}$sources
    elaborate -top $top -disable_auto_bbox -global_embedded_assumes
    foreach key {bbox_inst bbox_mod bbox_out stopat} {
        set values [get_design_info -list $key]
        record setup $key [llength $values]
        if {[llength $values]} {error "nonzero blackbox or stopat"}
    }
    clock clock
    reset -none
    assume -env -name initial_common_cold_reset -bound 1 {reset}
    assume -name no_later_cold_reset {initialized |=> !reset}
    record setup clock_mode single_posedge
    set identity [open executable.private w]
    puts $identity [info nameofexecutable]
    close $identity
    scope before
    set failed 0
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
            set failed 1
        }
        if {$expected eq "cex" && $info(validity_status) eq "cex"} {trace $label $item cex}
    }
    foreach label $covers {
        set item [property $label]
        prove -property [list $item] -time_limit $time_limit
        metadata cover.$label $item
        array set info [get_property_info $item]
        if {$info(type) ne "cover" || $info(disabled) ||
            $info(run_status) ne "processed" || $info(validity_status) ne "covered"} {
            set failed 1
        } else {
            trace $label $item cover
        }
    }
    scope after
    if {$failed} {error "native goals did not reach their required verdicts"}
    record run state complete
}
if {[catch {execute}]} {
    record run state failed
    close $records
    exit 1
}
close $records
exit 0
