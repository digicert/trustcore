
#ifndef __GEMALTO_CRYPTOKI__
#define __GEMALTO_CRYPTOKI__


  #if defined(_WINDOWS)
  
    #pragma pack(push, cryptoki, 1)
    
    // Specifies that the function is a DLL entry point
    #define CK_IMPORT_SPEC __declspec(dllimport)
    
    // Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do not define it in applications
    #ifdef CRYPTOKI_EXPORTS
      // Specified that the function is an exported DLL entry point
      #define CK_EXPORT_SPEC __declspec(dllexport)
    #else
      #define CK_EXPORT_SPEC CK_IMPORT_SPEC
    #endif
  
    // Ensures the calling convention for Win32 builds
    #define CK_CALL_SPEC __cdecl
  
    #define CK_PTR *
  
    #define CK_DEFINE_FUNCTION(returnType, name) \
      returnType CK_EXPORT_SPEC CK_CALL_SPEC name
  
    #define CK_DECLARE_FUNCTION(returnType, name) \
      returnType CK_EXPORT_SPEC CK_CALL_SPEC name
  
    #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
      returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)
  
    #define CK_CALLBACK_FUNCTION(returnType, name) \
      returnType (CK_CALL_SPEC CK_PTR name)
  
    #ifndef NULL_PTR
      #define NULL_PTR 0
    #endif
  
    #include "pkcs11.h"
    #include "pkcs-11v2-20a3.h"
  
    #pragma pack(pop, cryptoki)
  
  #else
  
    #define CK_PTR *
    
#ifdef __APPLE__
    #define CK_DEFINE_FUNCTION(returnType, name) \
      __attribute__((visibility("default"))) returnType name
#else   
    #define CK_DEFINE_FUNCTION(returnType, name) \
      returnType name
#endif
     
     #define CK_DECLARE_FUNCTION(returnType, name) \
      returnType name
    
    #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
      returnType (* name)
    
    #define CK_CALLBACK_FUNCTION(returnType, name) \
      returnType (* name)
    
    #define CK_ENTRY
  
    #ifndef NULL_PTR
      #define NULL_PTR 0
    #endif
  
    #include "pkcs11.h"
    #include "pkcs-11v2-20a3.h"

#endif

#endif // __GEMALTO_CRYPTOKI__
