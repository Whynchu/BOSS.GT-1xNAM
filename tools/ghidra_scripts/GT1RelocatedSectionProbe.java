// Bounded Thumb probe for a first relocated GT-1 code segment.
// The base and entry points come from firmware/work/reconstructed/entry-segments.json.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

public class GT1RelocatedSectionProbe extends GhidraScript {
    private long parse(String value) {
        return Long.decode(value);
    }

    @Override
    public void run() throws Exception {
        Address start = toAddr(0x01000300L);
        Address max = currentProgram.getMemory().getMaxAddress();
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM language missing TMode");
        currentProgram.getProgramContext().setValue(tmode, start, max, BigInteger.ONE);

        String[] args = getScriptArgs();
        Address[] seeds = new Address[args.length + 1];
        seeds[0] = start;
        for (int i = 0; i < args.length; i++) seeds[i + 1] = toAddr(parse(args[i]));
        for (Address seed : seeds) disassemble(seed);

        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        report.append("candidate_mapping=derived copy segment at 0x01000300; physical backing unverified\n");
        report.append("context=Thumb from traced entry; exact MB8AA4181 ISA unverified\n");
        report.append("seeds=");
        for (Address seed : seeds) report.append(seed).append(' ');
        report.append('\n');
        for (Address seed : seeds) append(report, seed, 180);

        String output = System.getenv("GT1_RELOCATED_GHIDRA_REPORT");
        if (output == null || output.isEmpty()) output = "firmware/work/ghidra-relocated-probe.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(output))) {
            writer.print(report);
        }
        println(report.toString());
    }

    private void append(StringBuilder output, Address seed, int count) {
        output.append("instructions_from_").append(seed).append(":\n");
        Instruction instruction = currentProgram.getListing().getInstructionAt(seed);
        for (int i = 0; instruction != null && i < count; i++) {
            output.append(instruction.getMinAddress()).append("  ").append(instruction.getMnemonicString());
            for (int op = 0; op < instruction.getNumOperands(); op++) {
                output.append(op == 0 ? "  " : ", ").append(instruction.getDefaultOperandRepresentation(op));
            }
            output.append('\n');
            instruction = instruction.getNext();
        }
    }
}
