// Check whether selected bootstrap literal-pool words have instruction xrefs.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.HashSet;

public class GT1Esc91ReferenceProbe extends GhidraScript {
    private final long[] fileOffsets = {0x74cL, 0x8ecL, 0xb04L, 0xbb8L};

    @Override
    public void run() throws Exception {
        Address blockStart = toAddr(0x00ffffd0L);
        Address blockEnd = toAddr(0x01001fcfL);
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM TMode register missing");
        currentProgram.getProgramContext().setValue(tmode, blockStart, blockEnd, BigInteger.ONE);
        disassemble(toAddr(0x010002c0L));
        disassemble(toAddr(0x01000ae4L));
        analyzeAll(currentProgram);

        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        report.append("mapping=runtime 0x00FFFFD0 + file_offset; scope=file offsets 0x0-0x1fff\n");
        report.append("method=Ghidra references to literal-pool addresses containing 0x02003000\n");
        Memory memory = currentProgram.getMemory();
        HashSet<String> emittedFunctions = new HashSet<>();
        for (long fileOffset : fileOffsets) {
            Address literalAddress = toAddr(0x00ffffd0L + fileOffset);
            int value = memory.getInt(literalAddress);
            report.append("literal file_offset=0x").append(Long.toHexString(fileOffset))
                .append(" runtime=").append(literalAddress)
                .append(" word=0x").append(Integer.toHexString(value)).append('\n');
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(literalAddress);
            int count = 0;
            while (refs.hasNext()) {
                Reference ref = refs.next();
                count++;
                Address from = ref.getFromAddress();
                Instruction instruction = currentProgram.getListing().getInstructionAt(from);
                report.append("  xref from=").append(from).append(" type=").append(ref.getReferenceType());
                if (instruction != null) {
                    report.append(" instruction=").append(instruction.getMnemonicString())
                        .append(' ').append(instruction.getDefaultOperandRepresentation(0));
                    if (instruction.getNumOperands() > 1)
                        report.append(", ").append(instruction.getDefaultOperandRepresentation(1));
                    report.append('\n');
                    appendInstructions(report, from, 24);
                    Function containing = currentProgram.getFunctionManager().getFunctionContaining(from);
                    if (containing != null) {
                        report.append("    containing_function=").append(containing.getEntryPoint()).append('\n');
                        ReferenceIterator callers = currentProgram.getReferenceManager().getReferencesTo(containing.getEntryPoint());
                        int callerCount = 0;
                        while (callers.hasNext()) {
                            Reference caller = callers.next();
                            callerCount++;
                            Address callerAddress = caller.getFromAddress();
                            Instruction callerInstruction = currentProgram.getListing().getInstructionAt(callerAddress);
                            report.append("      caller=").append(callerAddress).append(" type=").append(caller.getReferenceType());
                            if (callerInstruction != null)
                                report.append(" instruction=").append(callerInstruction.getMnemonicString())
                                    .append(' ').append(callerInstruction.getDefaultOperandRepresentation(0));
                            report.append('\n');
                        }
                        if (callerCount == 0) report.append("      callers=none in bounded Ghidra analysis\n");
                        if (emittedFunctions.add(containing.getEntryPoint().toString()))
                            appendFunction(report, containing);
                    } else {
                        report.append("    containing_function=unresolved\n");
                    }
                } else {
                    report.append('\n');
                }
            }
            if (count == 0) report.append("  xrefs=none in bounded Ghidra analysis\n");
        }
        String output = System.getenv("GT1_ESC91_REF_REPORT");
        if (output == null || output.isEmpty()) output = "firmware/work/ghidra-esc91-02003-refs.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(output))) { writer.print(report); }
        println(report.toString());
    }

    private void appendInstructions(StringBuilder report, Address start, int limit) {
        report.append("    code_from_").append(start).append(':').append('\n');
        Instruction instruction = currentProgram.getListing().getInstructionAt(start);
        for (int i = 0; instruction != null && i < limit; i++) {
            report.append("      ").append(instruction.getMinAddress()).append("  ")
                .append(instruction.getMnemonicString()).append("  ")
                .append(instruction.getDefaultOperandRepresentation(0));
            if (instruction.getNumOperands() > 1)
                report.append(", ").append(instruction.getDefaultOperandRepresentation(1));
            report.append('\n');
            instruction = instruction.getNext();
        }
    }

    private void appendFunction(StringBuilder report, Function function) {
        report.append("    full_function_").append(function.getEntryPoint()).append(":\n");
        ghidra.program.model.listing.InstructionIterator instructions =
            currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            report.append("      ").append(instruction.getMinAddress()).append("  ")
                .append(instruction.getMnemonicString()).append("  ")
                .append(instruction.getDefaultOperandRepresentation(0));
            if (instruction.getNumOperands() > 1)
                report.append(", ").append(instruction.getDefaultOperandRepresentation(1));
            report.append('\n');
        }
    }
}
