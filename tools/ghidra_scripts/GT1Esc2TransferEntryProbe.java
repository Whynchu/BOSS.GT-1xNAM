// Bounded explicit Thumb function decompilation/listing for one decoded GT-1 app image.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
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

public class GT1Esc2TransferEntryProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("need decoded app path and comma-separated entry addresses");
        byte[] decoded = Files.readAllBytes(Paths.get(args[0]));
        Address base = toAddr(0x60000000L);
        MemoryBlock existing = currentProgram.getMemory().getBlock(base);
        if (existing == null) {
            MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
                "DecodedImage_60000000", base, new ByteArrayInputStream(decoded), decoded.length, monitor, false);
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);
            block.setComment("Decoded GT-1 application at candidate runtime base 0x60000000; physical mapping unverified.");
        }
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM TMode register missing");
        currentProgram.getProgramContext().setValue(tmode, base, base.add(decoded.length - 1L), BigInteger.ONE);

        String[] seedStrings = args[1].split(",");
        StringBuilder out = new StringBuilder();
        out.append("program=").append(currentProgram.getName()).append('\n');
        out.append("language=").append(currentProgram.getLanguageID()).append('\n');
        out.append("mapping=decoded image at candidate 0x60000000; physical mapping unverified\n");
        out.append("method=bounded explicit Thumb seeds; functions are created/decompiled only at supplied entries\n");
        out.append("decoded_input=").append(args[0]).append('\n');
        out.append("seeds=").append(args[1]).append('\n');

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (String seed : seedStrings) {
                long value = Long.decode(seed.trim());
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
                Listing listing = currentProgram.getListing();
                var units = listing.getCodeUnits(function.getBody(), true);
                out.append("instruction_listing:\n");
                while (units.hasNext()) {
                    CodeUnit unit = units.next();
                    out.append(unit.getAddress()).append("  ").append(unit.toString()).append('\n');
                }
            }
        } finally {
            decompiler.dispose();
        }
        String reportPath = System.getenv("GT1_ESC2_TRANSFER_ENTRY_REPORT");
        if (reportPath == null || reportPath.isEmpty()) reportPath = "firmware/work/ghidra-esc2-transfer-entry-probe.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportPath))) { writer.print(out); }
        println(out.toString());
    }
}
