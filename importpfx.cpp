// IMPORTPFX.EXE
// Version 1.0
// Joe Klemencic  12/2002
// This program will import, delete and overwrite PKCS12 certificates in the specified store

#define _WIN32_WINNT 0x0500

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <cryptuiapi.h>
#include <string.h>


void DelCerts(char *pszIssuer, char *pszCertStore, char *pszNameString);
int Usage(void);

void main(int argc, char *argv[])
{
	WCHAR lpszCertStore[256];
	WCHAR pw[256];
	int iArgs, iRemove=0, iRemoveAll=0;;
	int iReqFlags=0;
	int iGotType=0;
	char *pszOUSubject;
	char *pszCertStore;
	char *pszInFile;
	char pszNameString[256];
	DWORD pszStoreType=NULL;

	for(iArgs=1;iArgs<argc;iArgs++){

		// If -f (pkcs12 filename)
		if(!stricmp(argv[iArgs], "-f")){
			pszInFile = argv[++iArgs];
			iReqFlags++;
		} // End if "-f"
		
		// If -p (password) param	
		if(!stricmp(argv[iArgs], "-p")){
			iArgs++;
			// Convert to WIDE
			MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, argv[iArgs], -1, pw, sizeof(pw)/sizeof(WCHAR) );
			mbstowcs(pw, argv[iArgs], strlen(argv[iArgs]));
			iReqFlags++;
		} // End if "-p"

		// If -t (Store Type)
		if(!stricmp(argv[iArgs], "-t")){
			iArgs++;
			if(!stricmp(argv[iArgs], "MACHINE")){
				pszStoreType=CERT_SYSTEM_STORE_LOCAL_MACHINE;
			} else {
				pszStoreType=CERT_SYSTEM_STORE_CURRENT_USER;	
			}
			iReqFlags++;
			iGotType=1;
		} // End if "-t"


		// If -s (Cert Store)
		if(!stricmp(argv[iArgs], "-s")){
			iArgs++;
			// convert to WCHAR pszOUSubject
			// Get the certificate store (normally is MY)
			MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, argv[iArgs], -1, lpszCertStore, sizeof(lpszCertStore)/sizeof(WCHAR) );
			mbstowcs(lpszCertStore, argv[iArgs], strlen(argv[iArgs]));
			pszCertStore=argv[iArgs];
			iReqFlags++;
		} // End if "-s"

		// If -r (Remove param), get the Subject OU (argc+1)
		if(!stricmp(argv[iArgs], "-r")){
				pszOUSubject = argv[++iArgs];
				if(!stricmp(pszOUSubject,"-all")){
					if(iGotType==1){
						iRemoveAll=1;
					} else {
						Usage();
					}
				}
				iRemove=1;
		} // End if "-r"
	} // End for iArgs



	if(iRemove && iRemoveAll){
		DelCerts(pszOUSubject, pszCertStore, NULL);
		exit(0);
	}

	if(iReqFlags != 4){
		Usage();
	}
	
	// read cert file
	BY_HANDLE_FILE_INFORMATION fileInfo;
	HANDLE hFile = CreateFile(pszInFile,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error: Couldn't open file (%s). Please check the PATH.\n", pszInFile);
		exit(1);
	}

	GetFileInformationByHandle(hFile,&fileInfo);
	long fileSize=fileInfo.nFileSizeLow;

	// make buffer for cert data
	PBYTE pbBuffer = NULL;
	if (!(pbBuffer=(PBYTE)malloc(fileSize)))
	{
		printf("Error: Could not allocate enough memory: (%l) bytes\n", fileSize);
		exit (1);
	}

	unsigned long bytesRead;
	ReadFile (hFile,pbBuffer,fileSize,&bytesRead,NULL);

	// create pfx blob
	CRYPT_DATA_BLOB cryptBlob;
	cryptBlob.cbData=fileSize;
	cryptBlob.pbData=pbBuffer;

	// is it actually a pfx blob?
	if (FALSE == PFXIsPFXBlob(&cryptBlob) )
	{
		printf("Error: Requested file is not a PKCS12 file.\n");
		exit(1);
	}

	HCERTSTORE hImportCertStore;

	hImportCertStore=PFXImportCertStore(&cryptBlob,(LPCWSTR)pw,CRYPT_USER_KEYSET);
	//hImportCertStore=PFXImportCertStore(&cryptBlob,(LPCWSTR)pw,CRYPT_MACHINE_KEYSET);
		if (hImportCertStore == NULL) 
	{
		printf("Error: Could not import the PKCS12 file\n");
		exit(1);
	}


	PCCERT_CONTEXT pCertContext = NULL;
	pCertContext= CertEnumCertificatesInStore(hImportCertStore,pCertContext);

	HCERTSTORE hMyCertStore;
	//if (!(hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER , (LPCSTR) lpszCertStore))) //L"MY")))
	if (!(hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, pszStoreType , (LPCSTR) lpszCertStore))){
	//if (!(hMyCertStore = CertOpenStore(CERT_STORE_PROV_REG, 0, NULL, pszStoreType , (LPCSTR) lpszCertStore))){
		printf("Error: Could not open the local %s certificate store.\n",pszCertStore);
		exit(1);
	}

	HCERTSTORE thisStore;
	
	thisStore = hMyCertStore;	
	CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128);
	printf("Certificate name: %s\n", pszNameString);

	if(iRemove){
		DelCerts(pszOUSubject, pszCertStore, pszNameString);
	}


	CertAddCertificateContextToStore(thisStore, pCertContext, CERT_STORE_ADD_ALWAYS, NULL);

	while (NULL != (pCertContext = CertEnumCertificatesInStore(hImportCertStore, pCertContext)))
	{
		CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128);
		printf("Certificate name: %s\n", pszNameString);

		thisStore = hMyCertStore;

		CertAddCertificateContextToStore(thisStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
	}

	// close stores
	CertCloseStore(hMyCertStore,0);
	CertCloseStore(hImportCertStore,0);

	printf("Successfully imported certificates in %s store.\n",pszCertStore);
	exit(0);

}




void DelCerts(char *pszIssuer, char *pszCertStore, char *pszUsername){
	//--------------------------------------------------------------------
	// Declare and initialize variables.

	HANDLE          hStoreHandle;
	PCCERT_CONTEXT  pCertContext=NULL;   
	PCCERT_CONTEXT  pDupCertContext; 

	char pszNameString[256];
	char pszIssuerString[256];
	int iOK2Del=0;


	//--------------------------------------------------------------------
	// Open a system certificate store.

	if ( !(hStoreHandle = CertOpenSystemStore(NULL, pszCertStore))){
		printf("The store was not opened.");
	} // End Open system store
	
	//-------------------------------------------------------------------
	// Find the certificates in the system store. 
	// on the first call to the function,
	// this parameter is NULL
	// on all subsequent calls, it is the last pointer returned by 
	// the function
	while(pCertContext= CertEnumCertificatesInStore(hStoreHandle, pCertContext)){
		//--------------------------------------------------------------------
		// Get the name of the subject of the certificate.
		if(!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, 128))){
			printf("CertGetName failed.");
		} // End get subject name

		// Get the Issuer of the cert
		if(!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, pszIssuerString, 128))){
			printf("CertGetName failed.");
		} // End get issuer name

		//--------------------------------------------------------------------
		// Check to determine whether the Issuer is the same as the subject OU
		if(!stricmp(pszIssuer, pszIssuerString)){
			// Check to ensure the Username = Subject CN
			if(!stricmp(pszUsername ,pszNameString)){
				iOK2Del=1;
			} // End stricmp username, subject CN
		} // End stricmp issuer, subject ou

		// If no pszUsername passed to the function, we are deleting ALL certs in the store
		if(pszUsername == NULL){
			iOK2Del = 1;
		} // End pszUsername == NULL

		if(iOK2Del){
			//-----------------------------------------------------------------
			// Create a duplicate pointer to the certificate to be 
			// deleted. In this way, the original pointer is not freed 
			// when the certificate is deleted from the store 
			// and the enumeration of the certificates in the store can
			// continue. If the original pointer is used, after the 
			// certificate is deleted, the enumeration loop stops.
			if(!(pDupCertContext = CertDuplicateCertificateContext(pCertContext))){
				printf("Duplication of the certificate pointer failed.");
			} // End if !pDupCertContext

			// Delete the certificate.
			if(!(CertDeleteCertificateFromStore(pDupCertContext))){
				printf("The deletion of the certificate failed.\n");
			} // End CertDeleteFromStore
			printf("Deleting cert from %s\n",pszIssuerString);
		} // End if(iOK2Del)
		iOK2Del = 0;
	} // end while

	//--------------------------------------------------------------------
	// Clean up.

	CertCloseStore(hStoreHandle, 0);


} // End DelCerts


int Usage(void){
	printf("IMPORTPFX v1.0	Joe Klemencic  2002\n\n");

	printf("Usage: importpfx.exe -f <filename.p12> -p <export passwd> -t USER|MACHINE -s <certstore> [-r \"Subject OU to remove\" | -all]\n");
	printf("\n");
	printf("This utility will import a PKCS12 certificate file (with a .p12 or .pfx\n");
	printf("extension) into the certificate store specified by the -s parameter.\n");
	printf("The default behavior is to overwrite like certificates (if available).\n");
	printf("The -r \"Subject OU\" will remove all certificates matching the Subject CN\n");
	printf("in from the CN in the PKCS12 file and the Subject OU set to the -r parameter.\n");
	printf("\n");
	printf("PARAMETERS:\n");
	printf("	-f  = PKCS12 filename\n");
	printf("	-p  = Password to secure the private key with\n");
	printf("	-t  = Store type (USER or MACHINE)\n");
	printf("	-s  = The certificate store to import into (MY is a common param)\n");
	printf("\n");
	printf("	-r \"Subject OU Text\"  = Delete all user certificates in which the\n");
	printf("	                        Subject OU matches the -r \"Subject OU Text\"\n");
	printf("                                and the Subject CN matches the PKCS12 Subject CN\n");
	printf("	-r -all  = Delete ALL user certificates in the <certstore>\n");
	printf("\n\n");
	printf("Examples:\n");
	printf("Import a PKCS12 file into the MY store, overwriting if allowed:\n");
	printf("	importpfs.exe -f x509.p12 -p \"password\" -t USER -s MY\n\n");
	printf("Import a PKCS12 file into the local machine Testing store and delete any\n");
	printf("stored certificates with a Subject containing OU=\"Self-Signed CA\":\n");
	printf("	importpfx.exe -f x509.p12 -p \"\" -t MACHINE -s Testing  -r \"Self-Signed CA\"\n");
	printf("\n");
	printf("Delete ALL certificates in the USER MY store:\n");
	printf("	importpfx.exe -t USER -s MY -r -all\n");
	printf("\n");
	exit(1);
}
