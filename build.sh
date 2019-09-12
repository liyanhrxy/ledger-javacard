# Replace with the path to your Java Card Development Kit
JCENV=/Users/liyan/java_workspace/ledger-javacard/sdks/jc304_kit
MAIN_APPLET_AID=0xFF:0x4C:0x45:0x47:0x52:0x2E:0x57:0x41:0x4C:0x54:0x30:0x31:0x2E:0x49:0x30:0x31
NDEF_APPLET_AID=0xFF:0x4C:0x45:0x47:0x52:0x2E:0x57:0x41:0x4C:0x54:0x30:0x31:0x2E:0x49:0x30:0x32
ELF_AID=0xFF:0x4C:0x45:0x47:0x52:0x2E:0x57:0x41:0x4C:0x54:0x30:0x31
mkdir -p build/classes build/applet build/src/com/ledger/wallet 2>/dev/null
cp src/com/ledger/wallet/*.java build/src/com/ledger/wallet
cpp -P src-preprocessed/com/ledger/wallet/Ripemd160.javap > build/src/com/ledger/wallet/Ripemd160.java
cpp -P src-preprocessed/com/ledger/wallet/SHA512.javap > build/src/com/ledger/wallet/SHA512.java
cpp -P -DNFC_2FA src-preprocessed/com/ledger/wallet/LedgerWalletApplet.javap > build/src/com/ledger/wallet/LedgerWalletApplet.java
javac -g -classpath $JCENV/lib/api_classic.jar -sourcepath build/src -d build/classes build/src/com/ledger/wallet/*.java 
java -classpath "$JCENV/lib/*" com.sun.javacard.converter.Main -exportpath "$JCENV/api_export_files" -useproxyclass -out CAP -classdir build/classes -d build/applet -applet $MAIN_APPLET_AID com.ledger.wallet.LedgerWalletApplet -applet $NDEF_APPLET_AID com.ledger.wallet.LWNFCForumApplet com.ledger.wallet $ELF_AID 1.0
cp build/applet/com/ledger/wallet/javacard/wallet.cap build/Ledger-wallet.cap 2>/dev/null
rm -rf build/applet
rm -rf build/classes
rm -rf build/src

