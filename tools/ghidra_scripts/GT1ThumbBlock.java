// Headless confirmation of the documented ARM/Thumb candidate in ESC91.000 only.
// The script deliberately does not select an ISA for GT1Upd or GT1Appli.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.SourceType;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

public class GT1ThumbBlock extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address blockStart = toAddr(0x00ffffd0L);
        Address blockEnd = toAddr(0x01001fcfL); // first 0x2000 file bytes, inclusive
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) {
            throw new IllegalStateException("Selected ARM language has no TMode context register");
        }
        currentProgram.getProgramContext().setValue(tmode, blockStart, blockEnd, BigInteger.ONE);

        Address earlyEntry = toAddr(0x010002c0L); // file offset 0x2f0, per verified map
        Address resetEntry = toAddr(0x01000ae4L); // vector PC 0x01000ae5 has Thumb bit set
        disassemble(earlyEntry);
        createFunction(earlyEntry, "ESC91_early_thumb_entry");
        disassemble(resetEntry);
        createFunction(resetEntry, "ESC91_reset_thumb_entry");
        analyzeAll(currentProgram);

        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        report.append("scope=file offsets 0x000000-0x001FFF only\n");
        report.append("mapping=runtime 0x00FFFFD0 + file_offset\n");
        report.append("TMode=1 across bounded first block\n");
        report.append("early_entry=file 0x2F0 runtime ").append(earlyEntry).append('\n');
        report.append("reset_entry=file 0xB14 runtime ").append(resetEntry).append('\n');

        int instructionCount = 0;
        for (Instruction instruction : currentProgram.getListing().getInstructions(true)) {
            if (instruction.getMinAddress().compareTo(blockStart) < 0 ||
                instruction.getMaxAddress().compareTo(blockEnd) > 0) {
                continue;
            }
            instructionCount++;
        }
        report.append("disassembled_instructions_in_block=").append(instructionCount).append('\n');
        appendInstructions(report, earlyEntry, 16);
        appendInstructions(report, resetEntry, 24);

        String outputPath = System.getenv("GT1_GHIDRA_REPORT");
        if (outputPath == null || outputPath.isEmpty()) {
            outputPath = "firmware/work/ghidra-esc91-thumb-analysis.txt";
        }
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputPath))) {
            writer.print(report.toString());
        }
        println(report.toString());
    }

    private void appendInstructions(StringBuilder report, Address start, int limit) {
        report.append("instructions_from_").append(start).append(':').append('\n');
        Instruction instruction = currentProgram.getListing().getInstructionAt(start);
        for (int i = 0; instruction != null && i < limit; i++) {
            report.append(instruction.getMinAddress()).append("  ")
                  .append(instruction.getMnemonicString()).append("  ")
                  .append(instruction.getDefaultOperandRepresentation(0));
            if (instruction.getNumOperands() > 1) {
                report.append(", ").append(instruction.getDefaultOperandRepresentation(1));
            }
            report.append('\n');
            instruction = instruction.getNext();
        }
    }
}
