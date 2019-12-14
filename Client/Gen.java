//import java.util.Random;
import java.security.SecureRandom;
import java.math.BigInteger;
import java.util.*;

public class Gen 
{
    final int BIT_SIZE = 32;

    BigInteger p;
    BigInteger q;
    BigInteger g;   
    BigInteger e;
    
    SecureRandom rnd;
    
    public Gen(String party)
    {
        rnd = new SecureRandom();   
        rnd.setSeed(System.currentTimeMillis());
        if(party.compareTo("Host") == 0)
        {
            generatePQ();
            //generateExponent();
            printDHParameters();
        }
    }

    public void generatePQ()
    {
        BigInteger r = returnRandEvenNumber(rnd);
        while(true)
        {
            q = new BigInteger(BIT_SIZE, 1, rnd);

            if(q.isProbablePrime(1))
            {
                break;
            }
        }

        while(true)
        {   
            r = returnRandEvenNumber(rnd);
            p = (r.multiply(q)).add(BigInteger.valueOf(1));
            if(p.isProbablePrime(1))
            {
                generateG(r);
                break;
            }
        }

    }

    public BigInteger returnRandEvenNumber(SecureRandom rnd)
    {
        BigInteger temp = new BigInteger(BIT_SIZE, rnd);
        while(true)
        {
            temp = new BigInteger(BIT_SIZE, rnd);
            if(temp.mod(BigInteger.valueOf(2)).compareTo(BigInteger.valueOf(0)) == 0)
            {
                break;
            }
        }
        return temp;
    }

    public BigInteger generateExponent()
    {
        return new BigInteger(BIT_SIZE, rnd);       
    }

    //Generate generator g
    public void generateG(BigInteger r)
    {
        BigInteger pMinus1 = p.subtract(BigInteger.valueOf(1));
        
        rnd.setSeed(System.currentTimeMillis());
        BigInteger h = new BigInteger(BIT_SIZE, rnd);
        
        while(true)
        {
            if(h.compareTo(BigInteger.valueOf(1)) == 1 && h.compareTo(pMinus1) == -1)
            {
               g = h.modPow(r, p);
               if(g.compareTo(BigInteger.valueOf(1)) == 1)
               {
                    return;
               }             
            }
            h = new BigInteger(BIT_SIZE, rnd);
        }
    }
    //Print p, q, g parameters to system
    public void printDHParameters()
    {
        System.out.println("p: " + p + "\n" + "q: " + q + "\n" + "g: " + g + "\n");
    }

    public Map<String, BigInteger> getPublicParameters()
    {

        Map<String, BigInteger> params = new HashMap<String, BigInteger>();
        params.put("g", g);
        params.put("p", p);
        return params;
    }

    public static void main(String args[]) 
    { 
        Gen dh = new Gen("Host");
        //Map<String, BigInteger> test = new HashMap<String, BigInteger>();
        //test = getParameters();
    }
}
