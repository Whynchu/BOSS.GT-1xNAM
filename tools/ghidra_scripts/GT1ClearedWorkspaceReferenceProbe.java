// Read-only cross-reference and literal scan for the application startup-cleared range.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GT1ClearedWorkspaceReferenceProbe extends GhidraScript {
    private static final long CLEAR_START = 0x602BADF0L;
    private static final long CLEAR_END = 0x604816B8L;
    private static final long DECODED_END = 0x602CD2B4L;

    private static class PointerWord {
        Address slot;
        long value;
        int xrefCount;
        String xrefs;
    }

    @Override
    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        AddressSetView initialized = memory.getAllInitializedAddressSet();
        StringBuilder out = new StringBuilder();
        out.append("program=").append(currentProgram.getName()).append('\n');
        out.append("method=read-only scan of defined code references and aligned 32-bit words into the v1.09 startup-cleared range\n");
        out.append(String.format("cleared_range=0x%08X-0x%08X length=%d\n", CLEAR_START, CLEAR_END, CLEAR_END-CLEAR_START));
        out.append(String.format("decoded_file_end_candidate=0x%08X\n", DECODED_END));

        int instructionCount = 0;
        int directRangeRefs = 0;
        int literalRangeRefs = 0;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(initialized, true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            instructionCount++;
            for (Reference reference : instruction.getReferencesFrom()) {
                Address target = reference.getToAddress();
                long targetValue = target.getOffset();
                if (inRange(targetValue)) {
                    directRangeRefs++;
                    out.append(String.format("direct_ref from=%s to=%s type=%s mnemonic=%s\n",
                        instruction.getAddress(), target, reference.getReferenceType(), instruction.getMnemonicString()));
                }
                if (memory.contains(target) && memory.contains(target.add(3))) {
                    long literalValue = Integer.toUnsignedLong(memory.getInt(target));
                    if (inRange(literalValue)) {
                        literalRangeRefs++;
                        out.append(String.format("literal_ref from=%s literal=%s value=0x%08X type=%s mnemonic=%s\n",
                            instruction.getAddress(), target, literalValue, reference.getReferenceType(), instruction.getMnemonicString()));
                    }
                }
            }
        }
        out.append(String.format("defined_instructions_scanned=%d direct_range_refs=%d literal_range_refs=%d\n",
            instructionCount, directRangeRefs, literalRangeRefs));

        List<PointerWord> tailWords = new ArrayList<>();
        Map<Long, Integer> targetCounts = new HashMap<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || !block.isRead()) continue;
            Address start = block.getStart();
            long offset = start.getOffset();
            long aligned = (offset + 3L) & ~3L;
            Address cursor = start.getAddressSpace().getAddress(aligned);
            while (cursor.compareTo(block.getEnd()) <= 0 && cursor.add(3).compareTo(block.getEnd()) <= 0) {
                long value = Integer.toUnsignedLong(memory.getInt(cursor)) & ~1L;
                if (value >= DECODED_END && value < CLEAR_END) {
                    targetCounts.put(value, targetCounts.getOrDefault(value, 0) + 1);
                    if (value >= DECODED_END) {
                        PointerWord item = new PointerWord();
                        item.slot = cursor;
                        item.value = value;
                        StringBuilder refs = new StringBuilder();
                        ReferenceIterator refIterator = currentProgram.getReferenceManager().getReferencesTo(cursor);
                        while (refIterator.hasNext()) {
                            Reference ref = refIterator.next();
                            if (refs.length() > 0) refs.append(',');
                            refs.append(ref.getFromAddress()).append('/').append(ref.getReferenceType());
                            item.xrefCount++;
                        }
                        item.xrefs = refs.toString();
                        if (item.xrefCount > 0) tailWords.add(item);
                    }
                }
                cursor = cursor.add(4);
            }
        }
        out.append("aligned_words_pointing_beyond_decoded_file_into_cleared_tail:\n");
        out.append("target_value_count=").append(targetCounts.values().stream().mapToInt(Integer::intValue).sum())
            .append(" unique_targets=").append(targetCounts.size()).append('\n');
        targetCounts.entrySet().stream().sorted(Map.Entry.<Long,Integer>comparingByValue().reversed()).limit(20)
            .forEach(entry -> out.append(String.format("  target=0x%08X count=%d\n", entry.getKey(), entry.getValue())));
        out.append("pointer_word_slots_with_Ghidra_xrefs:\n");
        tailWords.sort(Comparator.comparingInt((PointerWord item) -> item.xrefCount).reversed());
        for (int i = 0; i < Math.min(100, tailWords.size()); i++) {
            PointerWord item = tailWords.get(i);
            out.append(String.format("  slot=%s value=0x%08X refs=%d %s\n", item.slot, item.value, item.xrefCount, item.xrefs));
        }

        String reportPath = System.getenv("GT1_CLEARED_WORKSPACE_REPORT");
        if (reportPath != null && !reportPath.isEmpty()) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(reportPath))) { writer.print(out); }
        }
        println(out.toString());
    }

    private boolean inRange(long value) {
        return value >= CLEAR_START && value < CLEAR_END;
    }
}
