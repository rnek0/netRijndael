using System;
using System.Text;
using Rijndael.libs;

namespace Rijndael
{
    enum Fais{
        CRIPTE=1,
        DECRIPTE,
        SORTIR,
        ERROR
    }

    class Program
    {
        //private static byte[] tempcrypt = null;

        static void Main(string[] args)
        {
            var quit = false;
            Console.WriteLine($"CryptoSys! {DateTime.Now}");
            var control = 0;
            
            do
            {
                if(control >= 3){break;}
                Console.WriteLine("Faites un choix : [1] Cripter | [2] Decripter | [3] Sortir.");
                var choix = Console.ReadLine();

                // Protection sur le nombre de chars du choix.
                if(choix.Length > 1){
                    choix = "4";
                    //quit = true;
                }

                if(int.TryParse(choix,out int r)==false){
                    choix = "4";
                    control++;
                    //Console.WriteLine("control " + control);
                }

                var faire = int.Parse(choix);
                switch  (faire){
                    case (int)Rijndael.Fais.CRIPTE:
                        Console.WriteLine("Entrez la cléf pour crypter:");
                        var clefCrypt = Console.ReadLine();
                        Console.WriteLine("Entrez le texte a crypter:");
                        var textoInicial = Console.ReadLine();
                        Console.WriteLine($"Resultat chiffré: \n{Encriptacion(textoInicial, clefCrypt)}");
                    break;
                    case (int)Rijndael.Fais.DECRIPTE:
                        Console.WriteLine("Entrez la cléf pour decrypter:");
                        var clefDecrypt = Console.ReadLine();
                        Console.WriteLine("Entrez le texte a decrypter:");
                        var textoD = Console.ReadLine();
                        Console.WriteLine($"Resultat déchiffré: \n{DesEncriptacion(textoD, clefDecrypt)}");
                    break;
                    case (int)Rijndael.Fais.SORTIR:
                        Console.WriteLine("Merci, a bientôt !\n ");
                        quit = true;
                    break;
                    case (int)Rijndael.Fais.ERROR:
                        Console.WriteLine($"Choix erroné ! {control}/3\n");
                    break;
                    default:
                        Console.WriteLine("Entrées incoherentes, sortie...");
                        quit = true;
                    break;
                }
            } while (quit == false);          
        }

        /// <summary>
        /// Chiffre.
        /// </summary>
        /// <param name="textoEncriptado">Texte a chiffrér.</param>
        /// <param name="LLave">Cléf pour chiffrer.</param>
        private static string Encriptacion(string textoInicial, string LLave)
        {
            // La clef viens de l'exterieur, si tu l'oublies tant pis pour toi !
            var ArrayDeByteEncriptado = MiRijndael.Encriptar(textoInicial, LLave);
            //tempcrypt = ArrayDeByteEncriptado;
            var resultado = System.Text.Encoding.Unicode.GetString(ArrayDeByteEncriptado);
            
            // Sauvegarde de la dernière encryptation.
            System.IO.File.WriteAllText("TEXTE.txt",resultado);

            return resultado;
        }

        /// <summary>
        /// Decrypte.
        /// </summary>
        /// <param name="textoEncriptado">Texte chiffré.</param>
        /// <param name="LLave">Cléf pour decifrer.</param>
        private static string DesEncriptacion(string textoEncriptado, string LLave)
        {
            byte[] decriptetexto = System.Text.Encoding.Unicode.GetBytes(textoEncriptado);
            
            // La clef viens de l'exterieur, si tu l'oublies tant pis pour toi !
            var resultado = MiRijndael.Desencriptar(decriptetexto, LLave);
            return resultado;
        }
    }
}
