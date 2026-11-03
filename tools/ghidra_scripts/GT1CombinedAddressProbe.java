// Bounded probe with both the copied segment and decoded image mapped.
// Arguments: decoded-image.bin ENTRY_ADDRESS [ENTRY_ADDRESS ...]
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;

public class GT1CombinedAddressProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("need decoded image path and at least one entry address");
        byte[] decoded = Files.readAllBytes(Paths.get(args[0]));
        Address decodedBase = toAddr(0x60000000L);
        MemoryBlock decodedBlock = currentProgram.getMemory().createInitializedBlock(
            "DecodedImage_60000000", decodedBase, new ByteArrayInputStream(decoded),
            decoded.length, monitor, false);
        decodedBlock.setRead(true);
        decodedBlock.setExecute(true);
        decodedBlock.setComment("Decoded payload bytes at candidate runtime base 0x60000000; physical mapping unverified.");

        int[][] descriptorOffsets = {
            {0xE4, 0xE8, 0xEC}, {0xF8, 0xFC, 0x100}, {0x10C, 0x110, 0x114},
            {0x120, 0x124, 0x128}, {0x134, 0x138, 0x13C}, {0x148, 0x14C, 0x150}
        };
        StringBuilder mappedCopies = new StringBuilder();
        for (int i = 0; i < descriptorOffsets.length; i++) {
            int[] offsets = descriptorOffsets[i];
            long destination = Integer.toUnsignedLong(readInt(decoded, offsets[0]));
            long length = Integer.toUnsignedLong(readInt(decoded, offsets[1]));
            long sourceAddress = Integer.toUnsignedLong(readInt(decoded, offsets[2]));
            if (length == 0) continue;
            if (sourceAddress < 0x60000000L) throw new IllegalStateException("copy source outside decoded base");
            long sourceOffset = sourceAddress - 0x60000000L;
            if (sourceOffset + length > decoded.length) throw new IllegalStateException("copy source exceeds decoded image");
            Address destinationAddress = toAddr(destination);
            Address destinationEnd = destinationAddress.add(length - 1);
            ghidra.program.model.mem.MemoryBlock existing = currentProgram.getMemory().getBlock(destinationAddress);
            String action;
            if (existing != null && existing.getStart().compareTo(destinationAddress) <= 0 &&
                existing.getEnd().compareTo(destinationEnd) >= 0) {
                action = "already mapped by imported segment";
            } else {
                byte[] copied = java.util.Arrays.copyOfRange(decoded, (int) sourceOffset, (int) (sourceOffset + length));
                ghidra.program.model.mem.MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
                    "StartupCopy_" + i, destinationAddress, new ByteArrayInputStream(copied), length, monitor, false);
                block.setRead(true);
                block.setExecute(true);
                block.setComment("Copied from decoded image by startup descriptor; physical memory type unverified.");
                action = "mapped";
            }
            mappedCopies.append("descriptor_").append(i).append(" source=").append(Long.toHexString(sourceAddress))
                .append(" source_offset=").append(Long.toHexString(sourceOffset))
                .append(" destination=").append(Long.toHexString(destination))
                .append(" length=").append(Long.toHexString(length)).append(" action=").append(action).append('\n');
        }

        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM language missing TMode");
        currentProgram.getProgramContext().setValue(tmode, toAddr(0x01000300L),
            currentProgram.getMemory().getMaxAddress(), BigInteger.ONE);
        currentProgram.getProgramContext().setValue(tmode, decodedBase,
            decodedBase.add(decoded.length - 1L), BigInteger.ONE);

        Address[] seeds = new Address[args.length + 1];
        seeds[0] = toAddr(0x01000300L);
        seeds[1] = decodedBase;
        for (int i = 1; i < args.length; i++) seeds[i + 1] = toAddr(Long.decode(args[i]));
        for (Address seed : seeds) disassemble(seed);

        StringBuilder report = new StringBuilder();
        report.append("program=").append(currentProgram.getName()).append('\n');
        report.append("language=").append(currentProgram.getLanguageID()).append('\n');
        report.append("relocated_mapping=first copy segment at 0x01000300; physical backing unverified\n");
        report.append("decoded_mapping=decoded image at candidate 0x60000000; physical backing unverified\n");
        report.append("context=Thumb at traced starts; exact MB8AA4181 ISA unverified\n");
        report.append("decoded_input=").append(args[0]).append('\n');
        report.append("startup_copied_segments:\n").append(mappedCopies);
        report.append("seeds=");
        for (Address seed : seeds) report.append(seed).append(' ');
        report.append('\n');
        for (Address seed : seeds) append(report, seed, 200);

        String output = System.getenv("GT1_COMBINED_GHIDRA_REPORT");
        if (output == null || output.isEmpty()) output = "firmware/work/ghidra-combined-address-probe.txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(output))) { writer.print(report); }
        println(report.toString());
    }

    private int readInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8) |
            ((bytes[offset + 2] & 0xff) << 16) | ((bytes[offset + 3] & 0xff) << 24);
    }

    private void append(StringBuilder output, Address seed, int count) {
        output.append("instructions_from_").append(seed).append(":\n");
        Instruction instruction = currentProgram.getListing().getInstructionAt(seed);
        for (int i = 0; instruction != null && i < count; i++) {
            output.append(instruction.getMinAddress()).append("  ").append(instruction.getMnemonicString());
            for (int op = 0; op < instruction.getNumOperands(); op++)
                output.append(op == 0 ? "  " : ", ").append(instruction.getDefaultOperandRepresentation(op));
            output.append('\n');
            instruction = instruction.getNext();
        }
    }
}
