# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

source flow/report_metrics.tcl

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
    write_metrics reports/metrics.tsv $period_ns $output_load_ff
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
