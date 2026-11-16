# SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
# SPDX-License-Identifier: MIT
"""Keep ordering mutations tied to real fault propagation and execution."""

import unittest

from test.test_platform.axi_ordering import fault_suppression_witness, mutate


class OrderingMutationTests(unittest.TestCase):
    @staticmethod
    def fence_source(pause, declarations=""):
        return ("always @(posedge clock) m_fenceI <= isFenceI;\n" + declarations +
                "DitDahE2Fetch fetch (.pause(" + pause + "), .idle(idle));\n")

    def test_inline_fence_pause(self):
        source = self.fence_source("waiting | advance & isFenceI & ~fault")
        changed = mutate(source, "fence-i-as-nop")
        self.assertIn("m_fenceI <= 1'h0;", changed)
        self.assertIn(".pause(waiting | 1'h0)", changed)

    def test_factored_fence_pause_preserves_prediction_clear(self):
        source = self.fence_source("waiting | renamed & ~fault", "wire renamed = advance & isFenceI;\n")
        source += "DitDahE2BranchPrediction prediction (.clear(trap | renamed));\n"
        changed = mutate(source, "fence-i-as-nop")
        self.assertIn("wire renamed = advance & isFenceI;", changed)
        self.assertIn(".clear(trap | renamed)", changed)
        self.assertIn(".pause(waiting | 1'h0)", changed)

    def test_fence_pause_ignores_comments_and_other_ports(self):
        source = self.fence_source("waiting | advance & isFenceI & ~fault")
        source += "// .pause(advance & isFenceI & ~fault)\nwire observation = advance & isFenceI & ~fault;\n"
        changed = mutate(source, "fence-i-as-nop")
        self.assertIn("// .pause(advance & isFenceI & ~fault)", changed)
        self.assertIn("wire observation = advance & isFenceI & ~fault;", changed)

    def test_fence_mutation_rejects_missing_or_ambiguous_target(self):
        for source in (self.fence_source("waiting"),
                       self.fence_source("advance & isFenceI & ~fault | advance & isFenceI & ~fault"),
                       self.fence_source("waiting") + "wire other = advance & isFenceI & ~fault;\n",
                       self.fence_source("~(advance & isFenceI & ~fault)"),
                       self.fence_source("advance & isFenceI & ~fault & other"),
                       self.fence_source("alias & ~fault", "wire alias = advance | isFenceI;\n")):
            with self.subTest(source=source), self.assertRaisesRegex(AssertionError, "no longer matches"):
                mutate(source, "fence-i-as-nop")

    def test_fence_mutation_rejects_ambiguous_alias(self):
        source = self.fence_source("renamed & ~fault", "wire renamed = advance & isFenceI;\nassign renamed = waiting;\n")
        with self.assertRaisesRegex(AssertionError, "Ambiguous fence alias"):
            mutate(source, "fence-i-as-nop")

    def test_fence_mutation_requires_fetch_pause_owner(self):
        source = self.fence_source("advance & isFenceI & ~fault")
        with self.assertRaisesRegex(AssertionError, "fetch instance"):
            mutate(source.replace("DitDahE2Fetch fetch", "Other other"), "fence-i-as-nop")
        with self.assertRaisesRegex(AssertionError, "fetch pause"):
            mutate(source.replace(".pause", ".other"), "fence-i-as-nop")

    def test_inline_fault_and_unrelated_observation(self):
        source = """wire observation = data_response_bits_fault;
wire failed = m_trap | csrError | response & data_response_bits_fault;
wire trap = complete & failed;
"""
        changed = mutate(source, "ignored-data-fault")
        self.assertIn("wire observation = data_response_bits_fault;", changed)
        self.assertIn("m_trap | csrError | response & 1'h0;", changed)

    def test_factored_fault_through_renamed_aliases(self):
        source = """wire prior = m_trap | csrError;
wire responseError = response & data_response_bits_fault;
wire combined = prior | responseError;
assign trap = complete & combined;
"""
        changed = mutate(source, "ignored-data-fault")
        self.assertEqual(changed, source.replace("response & data_response_bits_fault", "response & 1'h0"))

    def test_comments_do_not_add_drivers_or_targets(self):
        source = """// wire trap = data_response_bits_fault;
wire responseError = response & data_response_bits_fault;
/* assign trap = data_response_bits_fault; */
wire trap = complete & responseError;
"""
        changed = mutate(source, "ignored-data-fault")
        self.assertIn("// wire trap = data_response_bits_fault;", changed)
        self.assertIn("/* assign trap = data_response_bits_fault; */", changed)
        self.assertIn("response & 1'h0", changed)

    def test_missing_fault_path_is_an_error(self):
        with self.assertRaisesRegex(AssertionError, "no longer matches"):
            mutate("wire observation = data_response_bits_fault; wire trap = complete & m_trap;", "ignored-data-fault")

    def test_missing_trap_is_an_error(self):
        with self.assertRaisesRegex(AssertionError, "Missing trap"):
            mutate("wire failed = response & data_response_bits_fault;", "ignored-data-fault")

    def test_multiple_fault_paths_are_an_error(self):
        source = """wire first = response & data_response_bits_fault;
wire second = response & data_response_bits_fault;
wire trap = complete & (first | second);
"""
        with self.assertRaisesRegex(AssertionError, "no longer matches"):
            mutate(source, "ignored-data-fault")

    def test_ambiguous_driver_is_an_error(self):
        source = """wire failed = response & data_response_bits_fault;
assign failed = m_trap;
wire trap = complete & failed;
"""
        with self.assertRaisesRegex(AssertionError, "Ambiguous"):
            mutate(source, "ignored-data-fault")

    @staticmethod
    def execution(*, fault=1, trap=0, retire_cycle=9):
        case = {"dataFault": 1024, "faultPc": 16, "words": {16: 0x0000A203}}
        trace = (f"Q 4 D 1024 0 0 0 2 1\nS 9 D 123 {fault}\n"
                 f"R {retire_cycle} 16 {case['words'][16]} 20 4 1 123 {trap} 5 1024\n")
        return trace, case

    def test_fault_mutant_executes_a_real_fault_response(self):
        trace, case = self.execution()
        self.assertEqual(fault_suppression_witness(trace, case), {"pc": 16, "responseCycle": 9, "retireCycle": 9})

    def test_fault_mutant_without_fault_response_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "injected data fault"):
            fault_suppression_witness(*self.execution(fault=0))

    def test_fault_mutant_without_suppression_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "did not suppress"):
            fault_suppression_witness(*self.execution(trap=1))

    def test_fault_mutant_requires_same_completion_edge(self):
        with self.assertRaisesRegex(AssertionError, "matching native completion"):
            fault_suppression_witness(*self.execution(retire_cycle=10))


if __name__ == "__main__":
    unittest.main()
