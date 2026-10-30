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
        array set info [get_property_info $item]
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
    global expected_assumptions
    record $tag clock [clock -list configuration -silent]
    record $tag reset [reset -list -typed_list -silent]
    set global [assume -list -silent -env]
    set reset [assume -reset -list -silent]
    record $tag global $global
    record $tag reset_assumptions $reset
    if {[string trim $global] ne "" || [string trim $reset] ne ""} {
        error "unexpected environment or reset assumption"
    }
    set enabled {}
    foreach item [get_property_list] {
        array unset info
        array set info [get_property_info $item]
        if {$info(type) eq "assume"} {
            if {$info(disabled) || $info(command) ne "assume"} {error "disabled assumption"}
            lappend enabled $info(name)
        }
    }
    record $tag assumptions [lsort $enabled]
    if {[lsort $enabled] ne [lsort $expected_assumptions]} {
        error "unexpected assumption set"
    }
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
    global sources top goals expected covers expected_assumptions time_limit
    analyze -sv12 {*}$sources
    elaborate -top $top -disable_auto_bbox
    foreach key {bbox_inst bbox_mod bbox_out stopat} {
        set values [get_design_info -list $key]
        record setup $key [llength $values]
        if {[llength $values]} {error "nonzero blackbox or stopat"}
    }
    clock clock
    reset -expression reset
    set_word_level_reduction on
    set_word_level_time_limit 30s
    set_proven_directive true
    record tool tcl_version [info patchlevel]
    # The executable path stays in the caller's private workspace.
    set identity [open executable.private w]
    puts $identity [info nameofexecutable]
    close $identity
    scope before
    set established [dict create]
    foreach row $goals {
        lassign $row label dependencies
        set selected {}
        foreach dependency $dependencies {
            if {![dict exists $established $dependency]} {error "unproved dependency"}
            lappend selected [dict get $established $dependency]
        }
        set item [property $label]
        metadata before.$label $item
        prove -property [concat $selected [list $item]] -time_limit $time_limit
        metadata final.$label $item
        array set info [get_property_info $item]
        if {$info(type) ne "assert" || $info(command) ne "assert" || $info(disabled) ||
            $info(run_status) ne "processed" || $info(validity_status) ne $expected} {
            error "native goal did not reach its required verdict"
        }
        if {$expected eq "proven"} {dict set established $label $item}
        if {$expected eq "cex"} {trace $label $item cex}
    }
    foreach label $covers {
        set item [property $label]
        prove -property [list $item] -time_limit $time_limit
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
if {[catch {execute} failure]} {
    record run state failed
}
close $records
exit
