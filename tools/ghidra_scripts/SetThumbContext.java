// Set Thumb context across an imported flat binary before auto-analysis.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import java.math.BigInteger;

public class SetThumbContext extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getMemory().getMinAddress();
        Address end = currentProgram.getMemory().getMaxAddress();
        Register tmode = currentProgram.getRegister("TMode");
        if (tmode == null) throw new IllegalStateException("ARM language missing TMode");
        currentProgram.getProgramContext().setValue(tmode, start, end, BigInteger.ONE);
        println("TMode=1 over " + start + ".." + end);
    }
}
