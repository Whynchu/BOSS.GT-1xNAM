// Find ARM-side references to the FA-08 ESC2 DSP interface and dump the
// containing functions. Read-only; the imported image is a flat binary at
// 0x60000000 with Thumb context set by SetThumbContext.java.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class FA08DspInterfaceProbe extends GhidraScript {
    private static final long[] TARGETS = {
        0x60003230L, // descriptor-driven DSP loader
        0x6000182EL, // block transfer into DSP windows
        0x60001C08L, // register/address write helper
        0x60001C28L, // bitfield write helper
        0x60001728L, // block copy helper
        0x60001DBEL, // second transfer/copy path
        0x60001C08L,
        0x601D2CB8L, // CDSPIF::change_dramio_rw_adrs string
        0x600C56D7L, // MACRO10 event-name table
    };

    @Override
    public void run() throws Exception {
        String output = System.getenv("FA08_DSP_REPORT");
        if (output == null || output.isEmpty()) output = "firmware/work/ghidra-fa08-dsp-interface.txt";

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        report.append("base=").append(currentProgram.getMemory().getMinAddress()).append('\n');
        report.append("note=bounded FA-08 ESC2 interface probe; exact DSP ISA remains unknown\n");

        Set<Function> functions = new LinkedHashSet<>();
        for (long target : TARGETS) {
            Address address = toAddr(target);
            report.append("\n=== target ").append(address).append('\n');
            Reference[] refs = getReferencesTo(address);
            report.append("references=").append(refs.length).append('\n');
            for (Reference ref : refs) {
                Address from = ref.getFromAddress();
                Function function = getFunctionContaining(from);
                report.append("  from ").append(from)
                      .append(" type=").append(ref.getReferenceType())
                      .append(" function=").append(function == null ? "?" : function.getName())
                      .append('\n');
                if (function != null) functions.add(function);
            }
        }

        for (Function function : functions) {
            report.append("\n===== function ").append(function.getName())
                  .append(" @ ").append(function.getEntryPoint()).append('\n');
            Instruction instruction = getInstructionAt(function.getEntryPoint());
            for (int i = 0; instruction != null && i < 220; i++) {
                report.append(instruction.getMinAddress()).append("  ")
                      .append(instruction.getMnemonicString());
                for (int op = 0; op < instruction.getNumOperands(); op++) {
                    report.append(op == 0 ? "  " : ", ")
                          .append(instruction.getDefaultOperandRepresentation(op));
                }
                report.append('\n');
                instruction = instruction.getNext();
            }
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                report.append("----- decompile -----\n");
                report.append(result.getDecompiledFunction().getC()).append('\n');
            }
        }

        try (PrintWriter writer = new PrintWriter(new FileWriter(output))) {
            writer.print(report);
        }
        println("wrote " + output + " (" + functions.size() + " functions)");
    }
}
