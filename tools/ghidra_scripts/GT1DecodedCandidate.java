// Exploratory import of the already decoded GT-1 application image.
// The 0x60000000 base is a candidate from header fields, not a proven CPU map.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

public class GT1DecodedCandidate extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = toAddr(0x60000000L);
        Address end = currentProgram.getMemory().getMaxAddress();
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM language missing TMode");
        currentProgram.getProgramContext().setValue(tmode, start, end, BigInteger.ONE);

        Address[] seeds = {start, toAddr(0x60000080L), toAddr(0x60000300L), toAddr(0x60000400L)};
        for (Address seed : seeds) disassemble(seed);
        // Keep this a bounded decoder probe. Global auto-analysis on a 2.9 MiB
        // raw blob creates many false functions and is not needed here.

        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        report.append("candidate_mapping=runtime 0x60000000 + decoded_output_offset; unverified\n");
        report.append("instruction_scope=Ghidra-decoded code units in first 0x200 bytes plus explicitly seeded offsets\n");
        int count = 0;
        for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
            if (ins.getMinAddress().compareTo(start) >= 0 &&
                ins.getMaxAddress().compareTo(toAddr(0x600001ffL)) <= 0) count++;
        }
        report.append("instruction_count_first_0x200=").append(count).append('\n');
        for (Address seed : seeds) append(report, seed, 40);

        String output = System.getenv("GT1_DECODED_GHIDRA_REPORT");
        if (output == null || output.isEmpty()) output = "firmware/work/ghidra-decoded-candidate.txt";
        try (PrintWriter w = new PrintWriter(new FileWriter(output))) { w.print(report); }
        println(report.toString());
    }

    private void append(StringBuilder out, Address seed, int count) {
        out.append("instructions_from_").append(seed).append(":\n");
        Instruction ins = currentProgram.getListing().getInstructionAt(seed);
        for (int i=0; ins != null && i<count; i++) {
            out.append(ins.getMinAddress()).append("  ").append(ins.getMnemonicString());
            for (int op=0; op<ins.getNumOperands(); op++) {
                out.append(op == 0 ? "  " : ", ").append(ins.getDefaultOperandRepresentation(op));
            }
            out.append('\n');
            ins = ins.getNext();
        }
    }
}
