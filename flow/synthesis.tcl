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

proc run_synthesis {} {
    source settings.tcl
    puts E2_SCRIPT_BEGIN
    set_host_options -max_cores $threads
    set references [split $::env(E2_NDM_LIBS) "\n"]
    create_lib -ref_libs $references -use_technology_lib [lindex $references 0] outputs/design.ndm
    set_svf outputs/mapping.svf
    set sources {}
    foreach name $rtl_files {
        lappend sources [file join rtl $name]
    }
    analyze -format sverilog $sources
    elaborate $top
    set_top_module $top
    set prior_scenarios [get_scenarios -quiet *]
    if {[sizeof_collection $prior_scenarios] != 0} {
        set_scenario_status $prior_scenarios -active false
    }
    create_mode functional
    create_corner typical
    create_scenario -mode functional -corner typical -name functional_typical
    current_scenario functional_typical
    set_scenario_status [get_scenarios functional_typical] -active true -setup true -hold true
    read_parasitic_tech -name estimated_rc -tlup $::env(E2_RC_FILE) -sanity_check advanced
    set_parasitic_parameters -corners [get_corners typical] -early_spec estimated_rc -late_spec estimated_rc
    source flow/synthesis_constraints.tcl
    set_dont_retime [all_registers -cells] true
    redirect -file reports/units.txt {report_units}
    redirect -variable unit_text {report_units}
    if {![regexp {length[[:space:]]*:[[:space:]]*1[.]00um} $unit_text]} {
        error "The area report requires micrometer length units"
    }
    redirect -file reports/setup-check.txt {check_design -checks netlist}
    set_qor_strategy -stage synthesis -metric timing
    compile_fusion -from initial_map -to initial_map
    initialize_floorplan -shape R -side_ratio {1 1} -core_utilization 0.5
    place_pins -self
    compile_fusion -from logic_opto -to logic_opto
    redirect -file reports/design-check.txt {check_design -checks pre_placement_stage}
    redirect -file reports/timing-check.txt {check_timing -scenarios [get_scenarios functional_typical] -all}
    redirect -file reports/qor.txt {report_qor -significant_digits 6}
    redirect -file reports/area.txt {report_area -physical -significant_digits 6}
    redirect -file reports/setup.txt {report_timing -delay_type max -max_paths 20 -significant_digits 6}
    redirect -file reports/hold.txt {report_timing -delay_type min -max_paths 20 -significant_digits 6}
    redirect -file reports/constraints.txt {report_constraints -all_violators -significant_digits 6}
    redirect -file reports/clocks.txt {report_clocks -attributes}
    redirect -file reports/scenarios.txt {report_scenarios}
    redirect -file reports/pvt.txt {report_pvt}
    set output [open reports/metrics.tsv w]
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
    save_block -label logic_opto
    save_lib [current_lib]
    write_verilog -hierarchy design outputs/mapped.v
    write_sdc -output outputs/mapped.sdc
    set_svf -off
    set output [open outputs/complete w]
    puts $output logic_opto
    close $output
}

if {[catch {run_synthesis} message options]} {
    set output [open reports/flow-error.txt w]
    puts $output $message
    puts $output [dict get $options -errorinfo]
    close $output
    exit 1
}
exit 0
