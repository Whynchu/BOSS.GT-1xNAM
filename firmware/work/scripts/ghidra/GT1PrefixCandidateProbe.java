// Exploratory, bounded ARM Thumb decode of the shared 194-byte section prefix.
// The start offsets are hypotheses; this script does not identify the ISA.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

public class GT1PrefixCandidateProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address prefixStart = toAddr(0);
        Address prefixEnd = toAddr(0xC1);
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM language has no TMode register");
        currentProgram.getProgramContext().setValue(tmode, prefixStart, prefixEnd, BigInteger.ONE);

        StringBuilder out = new StringBuilder();
        out.append("language=").append(currentProgram.getLanguageID()).append('\n');
        out.append("input_scope=shared section prefix file bytes 0x0-0xC1 (194 bytes)\n");
        out.append("candidate_offsets=0x5E and 0x60; exploratory only, no entry-point evidence\n");
        appendFrom(out, toAddr(0x5E), 32);
        appendFrom(out, toAddr(0x60), 32);
        String path = System.getenv("GT1_PREFIX_GHIDRA_REPORT");
        if (path == null || path.isEmpty()) path = "firmware/work/ghidra-prefix-candidate-probe.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(path))) { writer.print(out); }
        println(out.toString());
    }

    private void appendFrom(StringBuilder out, Address start, int limit) throws Exception {
        disassemble(start);
        out.append("instructions_from_").append(start).append(':').append('\n');
        Instruction instruction = currentProgram.getListing().getInstructionAt(start);
        for (int i = 0; instruction != null && i < limit; i++) {
            out.append(instruction.getMinAddress()).append("  ")
               .append(instruction.getMnemonicString()).append("  ")
               .append(instruction.getDefaultOperandRepresentation(0));
            if (instruction.getNumOperands() > 1) out.append(", ").append(instruction.getDefaultOperandRepresentation(1));
            out.append('\n');
            instruction = instruction.getNext();
        }
    }
}
