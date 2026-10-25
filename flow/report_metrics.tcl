# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

proc metric {stream name value} {
    puts $stream "$name\t$value"
}

proc timing_metrics {stream delay label} {
    set worst [get_timing_paths -delay_type $delay -max_paths 1]
    if {[sizeof_collection $worst] == 0} {
        metric $stream "${label}_worst_slack_ns" unavailable
        metric $stream "${label}_wns_ns" unavailable
        metric $stream "${label}_tns_ns" unavailable
        return
    }
    set slack [get_attribute $worst slack]
    metric $stream "${label}_worst_slack_ns" $slack
    metric $stream "${label}_wns_ns" [expr {min(0.0, $slack)}]
    set paths [get_timing_paths -delay_type $delay -slack_lesser_than 0.0 -nworst 1 -max_paths 100000]
    set total 0.0
    array set counts {input_to_register 0 register_to_register 0 register_to_output 0 input_to_output 0}
    array set worst_slack {input_to_register 0.0 register_to_register 0.0 register_to_output 0.0 input_to_output 0.0}
    foreach_in_collection path $paths {
        set path_slack [get_attribute $path slack]
        set total [expr {$total + $path_slack}]
        set start_class [get_attribute [get_attribute $path startpoint] object_class]
        set end_class [get_attribute [get_attribute $path endpoint] object_class]
        set from [expr {$start_class eq "port" ? "input" : "register"}]
        set to [expr {$end_class eq "port" ? "output" : "register"}]
        set kind "${from}_to_${to}"
        incr counts($kind)
        set worst_slack($kind) [expr {min($worst_slack($kind), $path_slack)}]
    }
    if {[sizeof_collection $paths] == 100000} {
        metric $stream "${label}_tns_ns" unavailable
    } else {
        metric $stream "${label}_tns_ns" $total
    }
    metric $stream "${label}_violating_paths" [sizeof_collection $paths]
    foreach kind [lsort [array names counts]] {
        metric $stream "${label}_${kind}_paths" $counts($kind)
        metric $stream "${label}_${kind}_wns_ns" $worst_slack($kind)
    }
}

proc write_metrics {path period_ns output_load_ff} {
    set output [open $path w]
    set cells [get_cells -hierarchical -filter {is_hierarchical == false}]
    set standard_area 0.0
    set memory_area 0.0
    set other_macro_area 0.0
    set standard_cells 0
    set memory_cells 0
    foreach_in_collection cell $cells {
        set area [get_attribute $cell area]
        if {[get_attribute $cell is_memory_cell]} {
            set memory_area [expr {$memory_area + $area}]
            incr memory_cells
        } elseif {[get_attribute $cell is_hard_macro]} {
            set other_macro_area [expr {$other_macro_area + $area}]
        } else {
            set standard_area [expr {$standard_area + $area}]
            incr standard_cells
        }
    }
    metric $output standard_cell_area_um2 $standard_area
    metric $output memory_area_um2 $memory_area
    metric $output other_macro_area_um2 $other_macro_area
    metric $output standard_cells $standard_cells
    metric $output memory_cells $memory_cells
    metric $output leaf_cells [sizeof_collection $cells]
    metric $output unmapped_cells [sizeof_collection [filter_collection $cells {is_unmapped == true}]]
    metric $output registers [sizeof_collection [all_registers -cells]]
    metric $output clocked_registers [sizeof_collection [all_registers -clock core_clock -cells]]
    metric $output latches [sizeof_collection [all_registers -level_sensitive -cells]]
    metric $output clocks [sizeof_collection [get_clocks *]]
    metric $output period_ns $period_ns
    metric $output output_load_pf [expr {$output_load_ff / 1000.0}]
    metric $output floorplan_utilization_target 0.5
    timing_metrics $output max setup
    timing_metrics $output min hold
    close $output
}
