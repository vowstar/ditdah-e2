# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Execute the production Tcl flows with controlled save results."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STUBS = r'''
set env(E2_NDM_LIBS) synthetic.ndm
set env(E2_RC_FILE) synthetic.rc
foreach command {
    set_host_options create_lib set_svf analyze elaborate set_top_module
    create_mode create_corner create_scenario current_scenario set_scenario_status
    read_parasitic_tech set_parasitic_parameters set_dont_retime set_qor_strategy
    check_design compile_fusion initialize_floorplan place_pins check_timing
    report_qor report_area report_timing report_constraints report_clocks
    report_scenarios report_pvt open_lib open_block set_app_options create_net
    create_port connect_net connect_pg_net clock_opt set_propagated_clock
    check_legality check_clock_trees report_clock_qor set_path_margin remove_path_margin
    set_latency_adjustment_options set_clock_latency
} {proc $command args {return 1}}
proc sizeof_collection {value} {return [llength $value]}
proc get_object_name {value} {return $value}
proc index_collection {value index} {return [lindex $value $index]}
proc get_blocks args {return synthetic.ndm:block/logic_opto.design}
proc get_scenarios args {
    if {[lindex $args 0] eq "-quiet"} {return {}}
    return functional_typical
}
proc get_corners args {return typical}
proc get_clocks args {return core_clock}
proc get_ports args {return [lindex $args end]}
proc all_registers args {return {}}
proc all_outputs args {return {}}
proc add_to_collection {left right} {return [concat $left $right]}
proc filter_collection {objects expression} {return $objects}
proc current_lib {} {return synthetic.ndm}
proc get_pins args {
    set filter [lindex $args [expr {[lsearch -exact $args -filter] + 1}]]
    if {$filter eq "port_type == power || port_type == nwell"} {return {power nwell}}
    if {$filter eq "port_type == ground || port_type == pwell"} {return {ground pwell}}
    if {$filter eq "port_type != signal"} {return {power ground nwell pwell}}
    error unexpected_pin_query
}
proc get_attribute {object attribute} {
    if {$attribute eq "port_type"} {return $object}
    error unexpected_attribute
}
proc get_nets args {
    if {[lindex $args 0] ne "-quiet"} {return [lindex $args 0]}
    if {[lindex $args end] in {power nwell}} {return VDD}
    return VSS
}
proc foreach_in_collection {name objects body} {
    upvar 1 $name object
    foreach object $objects {uplevel 1 $body}
}
proc report_units {} {return "length : 1.00um"}
proc redirect {mode destination body} {
    set value [uplevel 1 $body]
    if {$mode eq "-variable"} {
        upvar 1 $destination output
        set output $value
    } elseif {$mode eq "-file"} {
        set output [open $destination w]
        puts $output $value
        close $output
    } else {error unexpected_redirect}
}
proc write_verilog args {
    set output [open [lindex $args end] w]
    puts $output "module Core(); endmodule"
    close $output
}
proc write_sdc args {
    set output [open [lindex $args end] w]
    puts $output "create_clock -period 1.5 clock"
    close $output
}
proc save_result {operation} {
    set output [open reports/save-calls.txt a]
    puts $output $operation
    close $output
    if {$operation eq $::failure} {
        if {$::answer eq "error"} {error injected_save_error}
        return $::answer
    }
    return 1
}
proc save_block {option label} {
    if {$option ne "-label"} {error unexpected_save_option}
    return [save_result $label]
}
proc save_lib {library} {
    if {$library ne "synthetic.ndm"} {error unexpected_library}
    return [save_result library]
}
'''
SETTINGS = '''set threads 1
set rtl_files {Core.sv}
set top Core
set period_ns 1.5
set output_load_ff 2.0
set input_label logic_opto
set output_label clock_opt
set guidance_name physical
set power_net VDD
set ground_net VSS
set hold_margin_ns 0.0
'''
METRICS = '''proc write_metrics {path args} {
    set output [open $path w]
    puts $output "standard_cells\t1"
    close $output
}
proc metric {output name value} {puts $output "$name\t$value"}
'''

LATENCY_SETTINGS = '''set input_delay_ns 0.2
set output_delay_ns 0.2
set uncertainty_ns 0.05
set input_transition_ns 0.05
'''
LATENCY_STUBS = r'''
set clock_excluded 0
set reference_latency 0.25
set source_latency 0.125
set clock_propagated 0
set clock_tree_ready 0
proc clock_event {event} {
    set output [open reports/clock-events.txt a]
    puts $output $event
    close $output
}
proc interface_budget {name value} {
    set output [open reports/interface-budgets.tsv a]
    puts $output "$name\t$value"
    close $output
}
proc create_clock args {
    interface_budget period [lindex $args [expr {[lsearch -exact $args -period] + 1}]]
}
proc all_inputs {} {return {clock reset data_in}}
proc all_outputs {} {return data_out}
proc remove_from_collection {objects removed} {
    return [lsearch -all -inline -not -exact $objects $removed]
}
proc set_units args {}
proc set_clock_transition args {}
proc set_input_transition args {}
proc set_load args {}
proc set_clock_uncertainty {value clocks} {interface_budget uncertainty $value}
proc set_input_delay args {
    if {[lindex $args 1] ne "core_clock" || [lindex $args end] ne {reset data_in}} {
        error unexpected_input_reference
    }
    interface_budget input_[string trimleft [lindex $args 2] -] [lindex $args 3]
}
proc set_output_delay args {
    if {[lindex $args 1] ne "core_clock" || [lindex $args end] ne "data_out"} {
        error unexpected_output_reference
    }
    interface_budget output_[string trimleft [lindex $args 2] -] [lindex $args 3]
}
proc require_clock_boundary {} {
    if {!$::clock_excluded} {error "Automatic clock latency updates are not excluded"}
    if {$::reference_latency != 0.0} {error "IO reference boundary is not zero"}
    if {$::source_latency != 0.125} {error "Source latency changed"}
    if {$::clock_propagated != $::clock_tree_ready} {
        error "Clock propagation does not match the clock tree"
    }
}
proc set_latency_adjustment_options {option clocks} {
    if {$option ne "-exclude_clocks" || $clocks ne "core_clock"} {
        error unexpected_latency_exclusion
    }
    set ::clock_excluded 1
    clock_event exclude
}
proc set_clock_latency {value clocks} {
    if {$value != 0.0 || $clocks ne "core_clock"} {error unexpected_network_latency}
    if {!$::clock_excluded} {error "Automatic clock latency updates are not excluded"}
    set ::reference_latency 0.0
    set ::clock_propagated 0
    clock_event zero
}
proc compile_fusion args {
    require_clock_boundary
    clock_event compile
    return 1
}
proc clock_opt args {
    require_clock_boundary
    set ::clock_tree_ready 1
    set ::clock_propagated 1
    set ::reference_latency 0.25
    clock_event cts
    return 1
}
proc set_propagated_clock {clocks} {
    if {!$::clock_tree_ready} {error "Cannot propagate before clock insertion"}
    if {$::reference_latency != 0.0} {error "IO reference boundary is not zero"}
    set ::clock_propagated 1
    clock_event propagated
}
proc report_timing args {
    require_clock_boundary
    clock_event report
    return 1
}
rename save_result checkpoint_save_result
proc save_result {operation} {
    require_clock_boundary
    return [checkpoint_save_result $operation]
}
'''


class CheckpointSave(unittest.TestCase):
    def run_flow(self, flow, failure="none", answer="1", *, clock_reference=False,
                 source_text=None, expect_save=True):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        run = Path(temporary.name)
        for directory in ("flow", "reports", "outputs", "checkpoint/design.ndm", "rtl"):
            (run / directory).mkdir(parents=True, exist_ok=True)
        (run / "checkpoint/mapping.svf").write_text("synthetic guidance\n")
        (run / "settings.tcl").write_text(SETTINGS + (LATENCY_SETTINGS if clock_reference else ""))
        (run / "flow/report_metrics.tcl").write_text(METRICS)
        constraints = (ROOT / "flow/synthesis_constraints.tcl").read_text() if clock_reference else ""
        (run / "flow/synthesis_constraints.tcl").write_text(constraints)
        text = (ROOT / "flow" / (flow + ".tcl")).read_text() if source_text is None else source_text
        (run / "flow" / (flow + ".tcl")).write_text(text)
        driver = "set failure {" + failure + "}\nset answer {" + answer + "}\n" + STUBS
        if clock_reference:
            driver += LATENCY_STUBS
        driver += "\nsource flow/" + flow + ".tcl\n"
        (run / "driver.tcl").write_text(driver)
        result = subprocess.run(["tclsh", "driver.tcl"], cwd=run, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.stderr, "")
        if expect_save:
            self.assertTrue((run / "reports/save-calls.txt").exists(),
                            (run / "reports/flow-error.txt").read_text()
                            if (run / "reports/flow-error.txt").exists() else result.stdout)
        calls = ((run / "reports/save-calls.txt").read_text().splitlines()
                 if (run / "reports/save-calls.txt").exists() else [])
        return run, result, calls

    def test_success_reaches_expected_saves_and_completion(self):
        for flow, calls, label in (("synthesis", ["logic_opto", "library"], "logic_opto"),
                                   ("physical", ["placed", "clock_opt", "library"], "clock_opt")):
            with self.subTest(flow=flow):
                run, result, actual = self.run_flow(flow)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(actual, calls)
                self.assertEqual((run / "outputs/complete").read_text().strip(), label)
                self.assertTrue((run / "outputs/mapped.v").is_file())
                self.assertTrue((run / "outputs/mapped.sdc").is_file())
                self.assertFalse((run / "reports/flow-error.txt").exists())

    def check_failed_save(self, flow, failure, calls, message):
        for answer in ("0", "", "error"):
            with self.subTest(answer=answer):
                run, result, actual = self.run_flow(flow, failure, answer)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(actual, calls)
                self.assertFalse((run / "outputs/complete").exists())
                self.assertFalse((run / "outputs/mapped.v").exists())
                self.assertFalse((run / "outputs/mapped.sdc").exists())
                expected = "injected_save_error" if answer == "error" else message
                self.assertEqual((run / "reports/flow-error.txt").read_text().splitlines()[0], expected)

    def test_mapping_label_failure(self):
        self.check_failed_save("synthesis", "logic_opto", ["logic_opto"],
                               "Mapping checkpoint save failed")

    def test_mapping_library_failure(self):
        self.check_failed_save("synthesis", "library", ["logic_opto", "library"],
                               "Mapping library save failed")

    def test_placement_label_failure(self):
        self.check_failed_save("physical", "placed", ["placed"],
                               "Placement checkpoint save failed")

    def test_clock_label_failure(self):
        self.check_failed_save("physical", "clock_opt", ["placed", "clock_opt"],
                               "Clock checkpoint save failed")

    def test_clock_library_failure(self):
        self.check_failed_save("physical", "library", ["placed", "clock_opt", "library"],
                               "Clock library save failed")

    def test_clock_input_reference_preserves_interface_budgets(self):
        for flow, sequence in (("synthesis", ["exclude", "zero"]),
                               ("physical", ["exclude", "zero", "cts", "zero", "propagated"])):
            with self.subTest(flow=flow):
                run, result, _ = self.run_flow(flow, clock_reference=True)
                self.assertEqual(result.returncode, 0)
                events = (run / "reports/clock-events.txt").read_text().splitlines()
                self.assertEqual([event for event in events if event not in {"compile", "report"}], sequence)
                budgets = dict(line.split("\t") for line in
                               (run / "reports/interface-budgets.tsv").read_text().splitlines())
                self.assertEqual({name: float(value) for name, value in budgets.items()},
                                 {"period": 1.5, "uncertainty": 0.05, "input_max": 0.2,
                                  "input_min": 0.0, "output_max": 0.2, "output_min": 0.0})

    def test_clock_reference_rejects_missing_or_early_operations(self):
        zero = "    set_clock_latency 0.0 [get_clocks core_clock]\n"
        exclusion = "    set_latency_adjustment_options -exclude_clocks [get_clocks core_clock]\n"
        propagation = "    set_propagated_clock [get_clocks core_clock]\n"
        for flow in ("synthesis", "physical"):
            original = (ROOT / "flow" / (flow + ".tcl")).read_text()
            mutations = [(original.replace(exclusion, "", 1), "Automatic clock latency updates are not excluded"),
                         (original.replace(zero, "", 1), "IO reference boundary is not zero")]
            if flow == "physical":
                mutations.extend([
                    (original.replace(zero, zero + propagation, 1), "Cannot propagate before clock insertion"),
                    (original.replace(zero + propagation, propagation), "IO reference boundary is not zero"),
                    (original.replace(propagation, ""), "Clock propagation does not match the clock tree"),
                ])
            for changed, message in mutations:
                with self.subTest(flow=flow, message=message):
                    self.assertNotEqual(changed, original)
                    run, result, _ = self.run_flow(flow, clock_reference=True, source_text=changed,
                                                  expect_save=False)
                    self.assertEqual(result.returncode, 1)
                    self.assertFalse((run / "outputs/complete").exists())
                    self.assertFalse((run / "outputs/mapped.sdc").exists())
                    self.assertEqual((run / "reports/flow-error.txt").read_text().splitlines()[0], message)


if __name__ == "__main__":
    unittest.main()
