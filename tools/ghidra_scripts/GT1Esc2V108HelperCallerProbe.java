// Bounded v1.08 context for direct callers of the shared ESC2 transfer helper.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.address.AddressSet;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.math.BigInteger;

public class GT1Esc2V108HelperCallerProbe extends GhidraScript {
    private final long[] entries = {0x600080e0L, 0x600479f0L, 0x60047d30L};

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("need decoded v1.08 image");
        byte[] decoded = Files.readAllBytes(Paths.get(args[0]));
        Address base = toAddr(0x60000000L);
        MemoryBlock existing = currentProgram.getMemory().getBlock(base);
        if (existing == null) {
            MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
                "DecodedImage_60000000", base, new ByteArrayInputStream(decoded), decoded.length, monitor, false);
            block.setRead(true); block.setWrite(false); block.setExecute(true);
            block.setComment("Decoded v1.08 app at candidate 0x60000000; physical mapping unverified.");
        }
        Register tmode = currentProgram.getRegister("TMode");
        currentProgram.getProgramContext().setValue(tmode, base, base.add(decoded.length - 1L), BigInteger.ONE);
        DecompInterface decompiler = new DecompInterface(); decompiler.openProgram(currentProgram);
        StringBuilder out = new StringBuilder("v1.08 bounded Thumb helper-caller context; base mapping candidate only\n");
        try {
            for (long value : entries) {
                Address entry = toAddr(value); disassemble(entry);
                Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
                if (function == null) function = createFunction(entry, null);
                out.append("\nentry=").append(entry).append(" body=").append(function == null ? "none" : function.getBody()).append("\n");
                if (function != null) {
                    DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                    if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null)
                        out.append(result.getDecompiledFunction().getC()).append("\n");
                }
            }
            Listing listing = currentProgram.getListing();
            long[][] ranges = {{0x600080e0L,0x600081b0L},{0x60047a20L,0x60047a70L},{0x60047d50L,0x60047de0L}};
            for (long[] range : ranges) {
                Address start=toAddr(range[0]), end=toAddr(range[1]); out.append("\nlisting ").append(start).append("..").append(end).append("\n");
                var units=listing.getCodeUnits(new AddressSet(start,end),true);
                while(units.hasNext()) { CodeUnit unit=units.next(); out.append(unit.getAddress()).append("  ").append(unit.toString()).append("\n"); }
            }
        } finally { decompiler.dispose(); }
        String path = System.getenv("GT1_ESC2_V108_HELPER_CALLER_REPORT");
        if (path == null || path.isEmpty()) path = "firmware/work/ghidra-v108-esc2-helper-callers.txt";
        try(PrintWriter writer=new PrintWriter(new FileWriter(path))) { writer.print(out); }
        println(out.toString());
    }
}
