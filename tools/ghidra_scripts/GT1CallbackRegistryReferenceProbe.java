// Report Thumb LDR references to literals naming callback-0 registry storage.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

public class GT1CallbackRegistryReferenceProbe extends GhidraScript {
    private final long[] callbacks = {
        0x01002308L, 0x01001de8L, 0x010015fcL, 0x01002c78L,
        0x0100302cL, 0x01003250L, 0x01002fb0L, 0x010032c8L,
        0x010030a8L, 0x01001ce8L, 0x010014a4L, 0x010013aeL,
        0x01002f60L, 0x01002cf0L
    };

    @Override
    public void run() throws Exception {
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM TMode register missing");
        currentProgram.getProgramContext().setValue(tmode, toAddr(0x01000300L),
            currentProgram.getMemory().getMaxAddress(), BigInteger.ONE);
        for (long callback : callbacks) disassemble(toAddr(callback));

        StringBuilder out = new StringBuilder();
        out.append("program=").append(currentProgram.getName()).append('\n');
        out.append("method=Ghidra xrefs to copied-segment LDR literals whose words point into startup-zeroed registry storage or pool/task strings\n");
        out.append("callbacks=");
        for (long callback : callbacks) out.append(String.format("0x%08x ", callback));
        out.append('\n');
        for (long literal : new long[] {0x01000e7cL, 0x010023c0L, 0x01003894L, 0x01004010L,
                0x01000f1cL, 0x010010a8L, 0x01001358L, 0x0100222cL,
                0x010023c8L, 0x010024c4L, 0x010026a0L, 0x01002788L,
                0x0100359cL, 0x01003804L, 0x01001d94L, 0x01002234L,
                0x010026a8L, 0x01002790L, 0x010035a4L, 0x01003810L,
                0x01003fe8L}) {
            Address address = toAddr(literal);
            out.append(String.format("literal=0x%08x word=0x%08x\n", literal,
                currentProgram.getMemory().getInt(address)));
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(address);
            int count = 0;
            while (refs.hasNext()) {
                Reference ref = refs.next();
                count++;
                Address from = ref.getFromAddress();
                Instruction ins = currentProgram.getListing().getInstructionAt(from);
                out.append("  xref from=").append(from).append(" type=").append(ref.getReferenceType());
                if (ins != null) {
                    out.append(" instruction=").append(ins.getMnemonicString()).append(' ')
                        .append(ins.getDefaultOperandRepresentation(0));
                    if (ins.getNumOperands() > 1)
                        out.append(", ").append(ins.getDefaultOperandRepresentation(1));
                }
                out.append('\n');
            }
            if (count == 0) out.append("  xrefs=none\n");
        }
        String reportPath = System.getenv("GT1_CALLBACK_REGISTRY_REPORT");
        if (reportPath == null || reportPath.isEmpty()) reportPath = "firmware/work/gt1-callback-registry-xrefs.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(reportPath))) { writer.print(out); }
        println(out.toString());
    }
}
