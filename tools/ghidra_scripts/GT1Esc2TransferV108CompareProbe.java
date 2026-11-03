// Bounded v1.08 ESC2 transfer parser/helper comparison against the v1.09 map.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

public class GT1Esc2TransferV108CompareProbe extends GhidraScript {
    private final long[] entries = {
        0x60058d3cL, 0x60058e1cL, 0x600593a2L, 0x6005949cL,
        0x60093b14L, 0x6007cc2cL, 0x6007ccd0L, 0x6007cde2L,
        0x6007d686L
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("need decoded v1.08 application image path");
        byte[] decoded = Files.readAllBytes(Paths.get(args[0]));
        Address base = toAddr(0x60000000L);
        MemoryBlock existing = currentProgram.getMemory().getBlock(base);
        if (existing == null) {
            MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
                "DecodedImage_60000000", base, new ByteArrayInputStream(decoded), decoded.length, monitor, false);
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);
            block.setComment("Decoded v1.08 application at candidate runtime base 0x60000000; physical mapping unverified.");
        }
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM TMode register missing");
        currentProgram.getProgramContext().setValue(tmode, base, base.add(decoded.length - 1L), BigInteger.ONE);

        StringBuilder out = new StringBuilder();
        out.append("program=").append(currentProgram.getName()).append('\n');
        out.append("language=").append(currentProgram.getLanguageID()).append('\n');
        out.append("mapping=decoded v1.08 image at candidate 0x60000000; physical mapping unverified\n");
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
            Listing listing = currentProgram.getListing();
            long[][] ranges = {
                {0x6007cc2cL, 0x6007cd00L},
                {0x60093b14L, 0x60093c00L},
                {0x60058d3cL, 0x60058e70L},
                {0x6007cde2L, 0x6007d092L},
                {0x6007d790L, 0x6007d7c0L}
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
        String reportPath = System.getenv("GT1_ESC2_V108_COMPARE_REPORT");
        if (reportPath == null || reportPath.isEmpty()) reportPath = "firmware/work/ghidra-v108-esc2-transfer-compare.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportPath))) { writer.print(out); }
        println(out.toString());
    }
}
