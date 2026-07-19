import edu.mit.csail.sdg.alloy4.A4Reporter;
import edu.mit.csail.sdg.ast.Command;
import edu.mit.csail.sdg.ast.Module;
import edu.mit.csail.sdg.parser.CompUtil;
import edu.mit.csail.sdg.translator.A4Options;
import edu.mit.csail.sdg.translator.A4Solution;
import edu.mit.csail.sdg.translator.TranslateAlloyToKodkod;
import kodkod.engine.satlab.SATFactory;

/**
 * Headless Alloy runner for EP formal models.
 *
 * Compiles an .als file, executes every command (check + run), and reports the
 * outcome of each. Exit code is non-zero if any assertion (`check`) produces a
 * counterexample, or if any `run` predicate is unsatisfiable (a vacuous model),
 * or if the file fails to parse/translate. This lets CI gate on the models in
 * exactly the way the Alloy GUI's "Execute All" does, but without a display.
 *
 * check  command: SUCCESS  == UNSAT (no counterexample found) -> property holds
 * run    command: SUCCESS  == SAT   (instance found)          -> model non-vacuous
 *
 * Usage: java -cp .:alloy.jar AlloyCheck <file.als> [<file2.als> ...]
 */
public final class AlloyCheck {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: AlloyCheck <file.als> [<file.als> ...]");
            System.exit(2);
        }

        A4Reporter rep = new A4Reporter();
        A4Options opts = new A4Options();
        // SAT4J is the pure-Java solver bundled in the dist jar: no native
        // libraries, so the run is reproducible on any CI runner.
        opts.solver = SATFactory.find("sat4j").orElse(SATFactory.DEFAULT);

        int failures = 0;
        int totalChecks = 0, checksPassed = 0;
        int totalRuns = 0, runsSat = 0;

        for (String path : args) {
            System.out.println("========================================================");
            System.out.println("Model: " + path);
            System.out.println("========================================================");

            Module world;
            try {
                world = CompUtil.parseEverything_fromFile(rep, null, path);
            } catch (Throwable t) {
                System.out.println("  PARSE FAILED: " + t.getMessage());
                failures++;
                continue;
            }

            for (Command cmd : world.getAllCommands()) {
                boolean isCheck = cmd.check; // true for `check`, false for `run`
                A4Solution sol;
                try {
                    sol = TranslateAlloyToKodkod.execute_command(
                            rep, world.getAllReachableSigs(), cmd, opts);
                } catch (Throwable t) {
                    System.out.printf("  %-6s %-40s SOLVE ERROR: %s%n",
                            isCheck ? "check" : "run", cmd.label, t.getMessage());
                    failures++;
                    continue;
                }

                boolean sat = sol.satisfiable();
                if (isCheck) {
                    totalChecks++;
                    // A check passes iff the negation is UNSAT (no counterexample).
                    if (!sat) {
                        checksPassed++;
                        System.out.printf("  check  %-45s No counterexample found. OK%n", cmd.label);
                    } else {
                        System.out.printf("  check  %-45s COUNTEREXAMPLE FOUND -> property VIOLATED%n", cmd.label);
                        failures++;
                    }
                } else {
                    totalRuns++;
                    if (sat) {
                        runsSat++;
                        System.out.printf("  run    %-45s Instance found. (non-vacuous)%n", cmd.label);
                    } else {
                        System.out.printf("  run    %-45s NO INSTANCE -> model is VACUOUS%n", cmd.label);
                        failures++;
                    }
                }
            }
            System.out.println();
        }

        System.out.println("========================================================");
        System.out.printf("Results: checks %d/%d held, runs %d/%d satisfiable%n",
                checksPassed, totalChecks, runsSat, totalRuns);
        if (failures == 0) {
            System.out.println("OK: all assertions hold, all predicates consistent.");
        } else {
            System.out.println("FAIL: " + failures + " command(s) failed.");
        }
        System.out.println("========================================================");

        System.exit(failures == 0 ? 0 : 1);
    }
}
