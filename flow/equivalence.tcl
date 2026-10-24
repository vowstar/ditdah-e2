# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT

proc require_success {command} {
    if {![uplevel 1 $command]} {
        error "Formal setup command failed"
    }
}

proc run_equivalence {} {
    source settings.tcl
    puts E2_SCRIPT_BEGIN
    set_host_options -max_cores $threads
    set ::synopsys_auto_setup false
    set ::verification_assume_reg_init None
    set ::verification_set_undriven_signals BINARY:X
    set ::verification_clock_gate_edge_analysis true
    set ::hdlin_unresolved_modules error
    require_success {set_svf implementation/mapping.svf}
    foreach path $library_files {
        require_success {read_db -technology_library $path}
    }
    set sources {}
    foreach name $rtl_files {
        lappend sources [file join rtl $name]
    }
    require_success {read_sverilog -r $sources}
    require_success {set_top r:/WORK/$top}
    require_success {read_verilog -i -netlist implementation/mapped.v}
    require_success {set_top i:/WORK/$top}
    redirect -file reports/setup.txt {report_setup_status -all}
    redirect -file reports/black-boxes.txt {report_black_boxes -all}
    match
    redirect -file reports/unmatched.txt {report_unmatched_points}
    set passed [verify]
    redirect -file reports/status.txt {report_status}
    redirect -file reports/failing.txt {report_failing_points}
    redirect -file reports/aborted.txt {report_aborted_points}
    redirect -file reports/unverified.txt {report_unverified_points}
    redirect -file reports/guidance.txt {report_guidance -summary}
    save_session outputs/equivalence
    set output [open outputs/result.txt w]
    puts $output $passed
    close $output
    set output [open outputs/complete w]
    puts $output verification
    close $output
}

if {[catch {run_equivalence} message options]} {
    set output [open reports/flow-error.txt w]
    puts $output $message
    puts $output [dict get $options -errorinfo]
    close $output
    exit 1
}
exit 0
