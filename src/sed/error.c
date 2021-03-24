#include "../include/sed/error.h"

const struct error sedErrors[] = {
    {ECOMPW,    ERROR_WRITE_COMPLEXITY},
    {ECOMPR,    ERROR_READ_COMPLEXITY},
    {ENADMIN,   ERROR_NO_ADMIN},
    {EPGRANT,   ERROR_PERMISSION_GRANT},
    {ESMBR,     ERROR_SHADOW_MBR},
    {EERANGE,   ERROR_ERASE_RANGE},
    {EINSTALL,  ERROR_INSTALLATION},
    {ESPLOGIN,  ERROR_ADMINSP_LOGIN},
    {ESSESSION, ERROR_START_SESSION},
    {ENACCOUNT, ERROR_NO_ACCOUNT_EXIST},
    {EINIT,     ERROR_INITIALIZE_FAIL},
    {ECPINR,    ERROR_CPIN_ITERATION},
    {EIACCT,    ERROR_INVALID_ACCOUNT_TYPE},
    {ESTORER,   ERROR_DATASTORE_READ},
    {ESTOREW,   ERROR_DATASTORE_WRITE},  
    {ECPINW,    ERROR_CPIN_WRITE}, 
    {EICREDS,   ERROR_INVALID_CREDENTIALS},
    {EOWNED,    ERROR_DRIVE_OWNED},  
    {ELIFEC,    ERROR_LIFE_CYCLE},
    {EACTIVATE, ERROR_ACTIVATING},
    {ELRARG,    ERROR_LOCKING_RANGE_ARGUMENT},
    {EGENSET,   ERROR_GENERIC_SET},
    {EDELUSR,   ERROR_DELETING_USER},
    {ECLRSLT,   ERROR_CLEAR_SALT},
    {ECLRBLB,   ERROR_CLEAR_BLOB},
    {ECLRPASS,  ERROR_CLEAR_PASSWORD},
    {ECLRNME,   ERROR_CLEAR_NAME},
    {ESETNME,   ERROR_SET_NAME},
    {ECHNGNME,  ERROR_CHANGE_NAME},
    {EACCTEXT,  ERROR_ACCOUNT_EXIST},
    {EGETINFO,  ERROR_GET_INFO},
    {EUNLOCK,   ERROR_UNLOCK},
    {EUNMBR,    ERROR_UNSHADOW_MBR},
    {EIPASS,    ERROR_INVALID_PASSWORD},
    {EREVERT,   ERROR_REVERT},
    {EICHOICE,  ERROR_INVALID_CHOICE},
    {EERASE,    ERROR_ERASE},
    {EOFFSET,   ERROR_NO_OFFSET},
    {EHASH,     ERROR_HASH},
    {ESALT,     ERROR_SALT_GEN},
    {ENOFFSET,  ERROR_BAD_OFFSET},
    {EIAUTH,    ERROR_BAD_AUTH},
    {ELOCKCONF, ERROR_LOCKING_CONFIG},
    {ESTRINGMAX, ERROR_STRING_MAX_LENGTH},
    {ESMARTCARD, ERROR_SMART_CARD},
    {ECERT, ERROR_OBTAINING_CERT},
    {EPUBKEY, ERROR_PUBLIC_KEY},
    {EENCRYPT, ERROR_PUB_ENCRYPT},
    {EUSB, ERROR_USB},
    {ESETPASS, ERROR_SET_PASSWORD},
    {EENABLE, ERROR_ENABLE_USER},
    {EBADDRIVE, ERROR_BAD_DRIVE},
    {EMALLOC, ERROR_MALLOC},
    {EOPAL, ERROR_OPAL},
    {ELZERO, ERROR_LEVEL_ZERO},
    {EPROP, ERROR_PROPERTIES},
    {EIDENT, ERROR_IDENTITY},
    {EMUSER, ERROR_MAX_USERS},
    {EMADMIN, ERROR_MAX_ADMINS},
    {ELOGIN, ERROR_PASS_ATTEMPTS},
    {ENAMELEN, ERROR_NAME_LENGTH},
    {EPASSLEN, ERROR_PASS_LENGTH},
    {EBADINPUT, ERROR_BAD_INPUT},
    {EPBAEXIST, ERROR_PBA_NOT_EXIST},
    {EUSBMOUNT, ERROR_USB_MOUNT}
};

#define ERROR_COUNT ((sizeof(sedErrors)) / (sizeof(sedErrors[0])))

void sed_errors_print(int32_t error)
{
    if ((error & OPAL_ERROR) == OPAL_ERROR)
    {
        switch(error)
        {
            case OPAL_NOT_AUTHORIZED:
                fprintf(stderr, "SED Error: Permission denied by Tper\n");
                break;
            case OPAL_NO_SESSIONS_AVAILABLE:
                fprintf(stderr, "SED ERROR: No sessions available! A shutdown may be necessary\n");
                break;
            case OPAL_INVALID_PARAMETER:
                fprintf(stderr, "SED Error: Invalid Opal Parameter!\n");
                break;
            case OPAL_TPER_MALFUNCTION:
                fprintf(stderr, "SED Error: Tper Malfunction\n");
                break;
            case OPAL_AUTHORITY_LOCKED_OUT:
                fprintf(stderr, "SED Error: Authority locked out!\n");
                break;
            case OPAL_FAIL:
                fprintf(stderr, "SED Error: OPAL Fail\n");
                break;
            default:
                fprintf(stderr, "Unexpected error: 0x%x\n",error);
                break;
        }
    }

    else
    {
        switch(error)
        {
            case SED_ERROR_INVALID_DRIVE_PATH:
                fprintf(stderr, "SED Error: Can't open path to SED! Please verify path\n");
                break;
            case SED_ERROR_NOT_OPAL:
                fprintf(stderr, "SED Error: SED is not OPAL-compliant! Please verify\n");
                break;
            case SED_ERROR_IOCTL_FAILED:
                fprintf(stderr, "SED Error: Can't perform IOCTL! Try sudo?\n");
                break;
            case SED_ERROR_ALREADY_OWNED:
                fprintf(stderr, "SED Error: This SED has already been owned!\n");
                break;
            default:
                fprintf(stderr, "Unexpected Error 0x%x\n", error);
                break;
        }
    }
}

void sed_handleError(struct sedContext *sedCtx, int32_t error, char *msg)
{
    /* Print the error to the screen */ 
    sed_errors_print(error);
    
    /* Close any session that was started and cleanup */
    sed_cleanup(sedCtx);

    /* Print exit message */
    if (msg)
        printf("%s\n", msg);

    /* Exit the program since we reached a sed Error */
       exit(EXIT_FAILURE);
}

const char *getStringError(uint32_t errorNum)
{
    int i;

    for (i = 0; i < ERROR_COUNT; i++)
    {
        if (errorNum == sedErrors[i].errorNum)
            return sedErrors[i].errorString;
    }

    return ERROR_UNKNOWN_ERROR;
}

inline void printError(uint32_t errorNum)
{
    printf("Error: %s\n", getStringError(errorNum));
}
