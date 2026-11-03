// Bounded ARM/Thumb decode of the FA ESC90.000 bootstrap block only.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

public class FAESC90ThumbBlock extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address blockStart = toAddr(0x00ffffd0L);
        Address blockEnd = toAddr(0x01001fcfL);
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM language has no TMode context register");
        currentProgram.getProgramContext().setValue(tmode, blockStart, blockEnd, BigInteger.ONE);
        Address entry = toAddr(0x010002c4L); // file offset 0x2f4
        Address initLoop = toAddr(0x010009e8L); // file offset 0xa18, called by entry
        disassemble(entry);
        createFunction(entry, "FA_ESC90_early_thumb_entry");
        disassemble(initLoop);
        createFunction(initLoop, "FA_ESC90_init_table_loop");
        analyzeAll(currentProgram);

        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        report.append("scope=file offsets 0x000000-0x001FFF only\n");
        report.append("candidate_mapping=runtime 0x00FFFFD0 + file_offset\n");
        report.append("TMode=1 across bounded first block\n");
        report.append("entry=file 0x2F4 runtime ").append(entry).append('\n');
        report.append("init_loop=file 0xA18 runtime ").append(initLoop).append('\n');
        appendInstructions(report, entry, 12);
        appendInstructions(report, initLoop, 18);
        String path = System.getenv("FA_GHIDRA_REPORT");
        if (path == null || path.isEmpty()) path = "firmware/work/ghidra-fa-esc90-thumb-analysis.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(path))) { writer.print(report.toString()); }
        println(report.toString());
    }
    private void appendInstructions(StringBuilder report, Address start, int limit) {
        report.append("instructions_from_").append(start).append(':').append('\n');
        Instruction i = currentProgram.getListing().getInstructionAt(start);
        for (int n=0; i!=null && n<limit; n++) {
            report.append(i.getMinAddress()).append("  ").append(i.getMnemonicString()).append("  ")
                  .append(i.getDefaultOperandRepresentation(0));
            if (i.getNumOperands()>1) report.append(", ").append(i.getDefaultOperandRepresentation(1));
            report.append('\n'); i=i.getNext();
        }
    }
}
