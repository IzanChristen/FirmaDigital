import java.security.*;
import java.util.Base64;
import java.util.Scanner;


public class FirmaDigital {

    public static void main(String[] args) {
        try {
            //Generar par de claves
            KeyPair parClaves = generarParDeClaves();
            PrivateKey clavePrivada = parClaves.getPrivate();
            PublicKey clavePublica = parClaves.getPublic();
            System.out.println("Par de claves RSA generado correctamente.\n");

            //Leer mensaje
            Scanner sc = new Scanner(System.in);
            System.out.print("Introduce el mensaje a firmar: ");
            String mensaje = sc.nextLine();
            System.out.println();

            //Calcular hash
            byte[] hash = calcularHash(mensaje);
            System.out.println("Hash SHA-256 del mensaje: " + bytesAHex(hash) + "\n");

            //Firmar mensaje
            byte[] firma = firmarMensaje(mensaje, clavePrivada);
            System.out.println("Firma digital (Base64): " + Base64.getEncoder().encodeToString(firma) + "\n");

            //Verificar firma con mensaje original
            boolean validaOriginal = verificarFirma(mensaje, firma, clavePublica);
            if (validaOriginal) {
                System.out.println("Verificación con mensaje original: VALIDA\n");
            } else {
                System.out.println("Verificación con mensaje original: INVALIDA\n");
            }

            //Probar con mensaje modificado
            String mensajeAlterado = mensaje + " (modificado)";
            boolean validaAlterado = verificarFirma(mensajeAlterado, firma, clavePublica);
            System.out.println("Mensaje modificado: " + mensajeAlterado);
            if (validaAlterado) {
                System.out.println("Verificación con mensaje alterado: VALIDA (ERROR)\n");
            } else {
                System.out.println("Verificación con mensaje alterado: INVALIDA\n");
            }
            sc.close();

        } catch (Exception e) {
            System.err.println("Se produjo un error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static KeyPair generarParDeClaves() throws NoSuchAlgorithmException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        return generador.generateKeyPair();
    }

    private static byte[] calcularHash(String mensaje) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(mensaje.getBytes());
    }

    private static byte[] firmarMensaje(String mensaje, PrivateKey clavePrivada) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(clavePrivada);
        firma.update(mensaje.getBytes());
        return firma.sign();
    }

    private static boolean verificarFirma(String mensaje, byte[] firmaBytes, PublicKey clavePublica) throws Exception {
        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(clavePublica);
        verificador.update(mensaje.getBytes());
        return verificador.verify(firmaBytes);
    }

    private static String bytesAHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
