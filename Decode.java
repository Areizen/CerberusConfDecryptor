import java.util.Base64;

public class Decode {
    
    public class b
    {
        private int[] a;
        private int b;
        private int c;
        
        public b(final byte[] array) {
            super();
            this.b = 0;
            this.c = 0;
            this.a = this.c(array);
        }
        
        private void a(final int n, final int n2, final int[] array) {
            final int n3 = array[n];
            array[n] = array[n2];
            array[n2] = n3;
        }
        
        private int[] c(final byte[] array) {
            final int[] array2 = new int[256];
            final int n = 0;
            for (int i = 0; i < 256; ++i) {
                array2[i] = i;
            }
            int n2 = 0;
            for (int j = n; j < 256; ++j) {
                n2 = (n2 + array2[j] + array[j % array.length] + 256) % 256;
                this.a(j, n2, array2);
            }
            return array2;
        }
        
        public byte[] a(final byte[] array) {
            return this.b(array);
        }
        
        public byte[] b(final byte[] array) {
            final byte[] array2 = new byte[array.length];
            for (int i = 0; i < array.length; ++i) {
                this.b = (this.b + 1) % 256;
                final int c = this.c;
                final int[] a = this.a;
                final int b = this.b;
                this.a(b, this.c = (c + a[b]) % 256, a);
                final int[] a2 = this.a;
                array2[i] = (byte)(a2[(a2[this.b] + a2[this.c]) % 256] ^ array[i]);
            }
            return array2;
        }
    }


    public String a(String s) {
        try {
            s = new String(
                new b(
                    s.substring(0, 12).getBytes()
                    ).a(
                        this.b(
                            new String(
                                Base64.getDecoder().decode(
                                    s.substring(12)
                                    )
                                )
                            )
                        )
                    );
            return s;
        }
        catch (Exception ex) {
            return "";
        }
    }
    
    public byte[] b(final String s) {
        final int length = s.length();
        final byte[] array = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            array[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return array;
    }

    public static void main(String args[]){
        if(args.length != 1){
            System.out.println("Usage: <cipher> ");
            return;
        }

        System.out.println(new Decode().a(args[0]));
    }
}