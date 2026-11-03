// Bounded decompilation of ESC2 program/data transfer helper functions.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.math.BigInteger;

public class GT1Esc2ProtocolPathProbe extends GhidraScript {
    private final long[] entries = {
        0x60057940L, 0x60057a20L, 0x60057fa6L, 0x600580a0L,
        0x60056a22L, 0x60056ad2L, 0x60056efcL, 0x6005733eL,
        0x60008bd4L, 0x60094f24L, 0x6007e03cL, 0x6007e0e0L,
        0x6007e1f2L, 0x6007e20cL, 0x6007e732L, 0x6007ea96L
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("need decoded application image path");
        byte[] decoded = Files.readAllBytes(Paths.get(args[0]));
        Address base = toAddr(0x60000000L);
        MemoryBlock existing = currentProgram.getMemory().getBlock(base);
        if (existing == null) {
            MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
                "DecodedImage_60000000", base, new ByteArrayInputStream(decoded), decoded.length, monitor, false);
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);
            block.setComment("Decoded application at candidate runtime base 0x60000000; physical mapping unverified.");
        }
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM TMode register missing");
        currentProgram.getProgramContext().setValue(tmode, base, base.add(decoded.length - 1L), BigInteger.ONE);

        StringBuilder out = new StringBuilder();
        out.append("program=").append(currentProgram.getName()).append('\n');
        out.append("language=").append(currentProgram.getLanguageID()).append('\n');
        out.append("mapping=decoded image at candidate 0x60000000; physical mapping unverified\n");
        out.append("method=bounded explicit Thumb seeds; create and decompile only listed entries\n");
        out.append("decoded_input=").append(args[0]).append('\n');
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (long value : entries) {
                Address entry = toAddr(value);
                disassemble(entry);
                Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (function == null) function = createFunction(entry, null);
                out.append("\nentry=").append(entry).append('\n');
                if (function == null) {
                    out.append("function_creation=failed\n");
                    continue;
                }
                out.append("function_body=").append(function.getBody()).append('\n');
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    out.append("decompile_status=failed ").append(result == null ? "no result" : result.getErrorMessage()).append('\n');
                } else {
                    out.append(result.getDecompiledFunction().getC()).append('\n');
                }
            }
            // Preserve the actual listing for the large parser whose PIC control flow
            // decompiles with warnings. This is evidence, not a claim that the chosen
            // address mapping or function boundaries are physically correct.
            Listing listing = currentProgram.getListing();
            long[][] ranges = {
                {0x6007e1f2L, 0x6007e4a7L},
                {0x6007e732L, 0x6007e7e0L},
                {0x6007ea96L, 0x6007ebd0L}
            };
            for (long[] range : ranges) {
                Address start = toAddr(range[0]);
                Address end = toAddr(range[1]);
                out.append("\nassembly_listing=[").append(start).append(", ").append(end).append("]\n");
                var units = listing.getCodeUnits(new AddressSet(start, end), true);
                while (units.hasNext()) {
                    CodeUnit unit = units.next();
                    out.append(unit.getAddress()).append("  ").append(unit.toString()).append('\n');
                }
            }
        } finally {
            decompiler.dispose();
        }
        String reportPath = System.getenv("GT1_ESC2_TRANSFER_DECOMPILE_REPORT");
        if (reportPath == null || reportPath.isEmpty()) reportPath = "firmware/work/ghidra-v109-esc2-protocol-path.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportPath))) { writer.print(out); }
        println(out.toString());
    }
}
