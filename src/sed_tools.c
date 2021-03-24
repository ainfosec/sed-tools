#include <stdio.h>
#include <getopt.h>
#include <ctype.h>
#include "../src/include/sed/sed.h"
#include "../src/include/password/sedAuth.h"


char verbose = 0;
char defaultAccount = 0;

static const struct option longOptions[] =
{
    {"default-account", no_argument, NULL, 'D'},
    {"zdiscovery", no_argument, NULL, 'z'},
    {"setup", no_argument, NULL, 's'},
    {"iso", required_argument, NULL, 'i'},
    {"revert", required_argument, NULL, 'r'},
    {"psid-revert", required_argument, NULL, 'R'},
    {"create-user", no_argument, NULL, 'c'},
    {"delete-user", no_argument, NULL, 'C'},
    {"lock-drive", no_argument, NULL, 'l'},
    {"unlock-drive", no_argument, NULL, 'u'},
    {"unshadow-drive", no_argument, NULL, 'U'},
    {"list-accounts", no_argument, NULL, 'a'},
    {"list-complexity", no_argument, NULL, 'p'},
    {"modify-complexity", no_argument, NULL, 'P'},
    {"change-username", no_argument, NULL, 'm'},
    {"user", required_argument, NULL, 'o'},
    {"newname", required_argument, NULL, 'n'},
    {"change-password", no_argument, NULL, 't'},
    {"authtype", required_argument, NULL, 'A'},
    {"account-type", required_argument, NULL, 'g'},
    {"secure-erase", no_argument, NULL, 'e'},
    {"test-login", no_argument, NULL, 'T'},
    {"boot-pba", no_argument, NULL, 'b'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0}
};

void help(void)
{
    printf("\n");
    printf("Usage:    sed_tools [device] [options]\n\n");
    printf("Options: \n");
    printf(" -D, --default-account   Use Default account information. (Used For testing)\n");
    printf(" -z, --zdiscovery        Performs a level 0 discovery on the Opal drive, which returns detailed information about the drive\n");
    printf(" -s, --setup             Setup Sed-tools on Opal Self-encrypting drive\n");
    printf(" -i, --iso               Pre-boot Authentication Image to install on Opal Drive\n");
    printf(" -r, --revert            Revert Tper. Put Opal Drive back to it's original Manufactured State\n");
    printf(" -R, --psid-revert       PSID Revert Tper. Put Opal Drive back to it's original Manufactured State using its PSID\n");
    printf(" -c, --create-user       Create a new Account on the Opal Drive\n"); 
    printf(" -A, --authtype          Set authentication type. This can be \"password\", \"usb\", \"2password\", \"smartcard\", \"smartcard+password\"\n");
    printf(" -g, --account-type      Set the account type. This can be \"User\", \"Admin\", or \"Distress\"\n");
    printf(" -C, --delete-user       Delete an account from the Opal Drive\n");
    printf(" -l, --lock-drive        Locks the opal drive. \n");
    printf(" -u, --unlock-drive      Unlocks the Opal drive\n");
    printf(" -U, --unshadow-drive    Unshadow the MBR. Temporarily restore original MBR\n");
    printf(" -a, --list-accounts     List all accounts on the Opal Drive\n");
    printf(" -p, --list-complexity   Displays the current password complexity settings\n");
    printf(" -P, --modify-complexity Modifies the password complexty\n");
    printf(" -m, --change-username   Change the name of a current user\n");
    printf(" -o  --user              Old name to get changed\n");
    printf(" -n  --newname           Username to operate with. If this is used with createUser, then this becomes the oldname\n");
    printf(" -t, --change-password   Change the current password and/or Authentication type\n");
    printf(" -T, --test-login        Test a username and password for correct Authentication\n");
    printf(" -e, --secure-erase      Wipe all data from drive, besides the Opal Stuff(i.e accounts and locking range)\n");
    printf(" -b, --boot-pba          Runs the PBA code. Should be executed at system boot");
    printf(" -v, --verbose           Verbose, Enable verbose output mode\n");
    printf(" -h, --help              Help, print usage\n\n");
}

uint32_t revert(struct sedContext *sedCtx, char *password)
{
    printf("%s\n%s\n\n", INITIATE_REVERT, REVERT_WARNING);
    
    if (sed_revertDrive(sedCtx, password))
        return sedError;

    printf("%s\n", REVERT_SUCCESS);
    return 0;
}

uint32_t psidRevert(struct sedContext *sedCtx, char *password)
{
    printf("%s\n%s\n\n", INITIATE_REVERT, REVERT_WARNING);

    if (sed_psidRevert(sedCtx, password))
    {
        printError(sedError);
        return sedError;
    }
    
    printf("%s\n", REVERT_SUCCESS);
    return 0;
}

uint32_t deleteAccount(struct sedContext *sedCtx, char *user)
{
    /* Need admin Privilege */
    if (promptAdminLogin(sedCtx))
        return sedError;

    if (deleteUser(sedCtx, user))
        return sedError;
    

    printf("%s\n", DELETE_USER_SUCCESS);

    return sedError;
}

uint32_t listAccounts(struct sedContext *sedCtx)
{
    if (sed_startSessionAsAnybody(sedCtx, Admin))
        return sedError;

    printf("Username\t\tAccount Type\n");
    printf("--------\t\t------------\n");

    sedError = listAllAccounts(sedCtx);

    return sedError;
}

uint32_t listComplexity(struct sedContext *sedCtx)
{
    struct password_complexity complexity;
    
    if (sed_startSessionAsAnybody(sedCtx, Admin))
        return sedError;

    sedError = getPasswordRequirements(sedCtx, &complexity);

    if (!sedError)
        displayPasswordComplexity(sedCtx, &complexity);

    return sedError;
}

uint32_t testLogin(struct sedContext *sedCtx, char *user)
{

    if (defaultAccount)
    {
        if (loginWithDefaultAccount(sedCtx, Admin))
            return sedError;
    }

    else
    {
        if (sed_startSessionAsAnybody(sedCtx, User))
            return sedError;
        if (authenticate(sedCtx, user))
            return sedError;
    }

    printf("Successfully Logged In with Account Information\n");
    return 0;
}

uint32_t createAccount(struct sedContext *sedCtx, char *username, char *authType, SedAccounts accountType)
{
    struct userInfo user;


    /* Needs admin privilege. Current account is not admin */
    if (promptAdminLogin(sedCtx))
        return sedError;

    /* Update user struct */

    if (strlen(username) > MAX_NAME_LENGTH)
        return ENAMELEN;

    strncpy(user.userName, username, sizeof(user.userName));   

    user.accountType = accountType;


    /* Make sure we didnt exceed the number of Users and Admins */
    user.id = getNextAvailableID(sedCtx, user.accountType);
    if (sedError)
        return sedError;
    
    user.authenticationType = getAuthenticationFromString(sedCtx, authType);

    /* Create user with gathered credentials */
    if (createUser(sedCtx, user))
        return sedError;

    
    printf("Successfully Created %s\n", user.userName);

    return 0;
}

uint32_t lockDrive(struct sedContext *sedCtx)
{
    char username[MAX_NAME_LENGTH] = {0};

    if (defaultAccount)
    {
        if (loginWithDefaultAccount(sedCtx, Admin))
            return sedError;
    }
    
    else
    {
        if (promptUsername(sedCtx, username, 0))
            return sedError;

        if (authenticate(sedCtx, username))
            return sedError; 
    }

    if (sed_lockDrive(sedCtx))
        return sedError;
    
    if (!sedError)
        printf("[+] Drive Locked.\n");

    return sedError;
}

uint32_t unlockDrive(struct sedContext *sedCtx)
{
    char username[MAX_NAME_LENGTH] = {0};

    if (defaultAccount)
    {
        if (loginWithDefaultAccount(sedCtx, Admin))
            return sedError;
    }

    else
    {
        if (promptUsername(sedCtx, username, 0))
            return sedError;

        if (authenticate(sedCtx, username))
            return sedError; 
    }

    if (sed_unlockDrive(sedCtx))
        return sedError;
    
    if (!sedError)
        printf("[+] Drive Unlocked.\n");

    return sedError;
}

uint32_t bootPBA(struct sedContext *sedCtx)
{
    struct userInfo account;
    uint32_t attempts = 0;

    /* Need to start a session as anybody in order to parse the datastore */
    if (sed_startSessionAsAnybody(sedCtx, User))
        return sedError;

    /* Presents the initial login screen. Allows user to type in their account name, and it
    performs a lookup based on the username */
    while (attempts <  MAX_ATTEMPTS)
    {
        if (userNameScreen(sedCtx, account.userName))
        {
            fprintf(stderr, "Invalid Username.\n");
            sleep(DELAY);
            attempts++;
        }

        else
            break;
    }

    if (attempts == MAX_ATTEMPTS)
        return (sedError = ELOGIN);
        
    /* Automatically find authType and login based on that */
    if (authenticationScreen(sedCtx, account.userName))
        return sedError;

    /* Get account type. If its an admin, then it can go to admin menu */
    if (getUserInformationFromUserName(sedCtx, &account))
        return sedError;

    if (account.accountType == User)
        bootDrive(sedCtx);
    
    else if (account.accountType == Admin)
        adminLogin(sedCtx);
         
    else
        return (sedError = EICREDS);

    return sedError;
}

uint32_t promptChangeUsername(struct sedContext *sedCtx, char *oldName, char *newName)
{
    /* Need admin Privilege */
    if (promptAdminLogin(sedCtx))
        return sedError;
    
    /* See if the new name already belongs to someone */ 
    if (searchForUser(sedCtx, newName))
        return (sedError = EACCTEXT);

    /* Make sure the name they want to change exist  */ 
    if (!searchForUser(sedCtx, oldName))
        return (sedError = ENACCOUNT);
    
    /* Update the userName with the new name */
    if (changeUserName(sedCtx, oldName, newName))
        return sedError;

    /* Successfully changed the userName */
    printf("%s to %s\n", CHANGE_NAME_SUCCESS, newName);

    return sedError;
}

uint32_t promptChangePassword(struct sedContext *sedCtx, char *username, char *authtype)
{
    struct userInfo user;

    /* Need admin Privilege */
    if (promptAdminLogin(sedCtx))
        return sedError;
    
    /* Update user struct */
    strcpy(user.userName, username); 
    
    if (getUserInformationFromUserName(sedCtx, &user))
        return (sedError = EGETINFO);   

    user.authenticationType = getAuthenticationFromString(sedCtx, authtype);

    /* Change the authentication type */
    if (setupNewAuth(sedCtx, user))
        return sedError;

    /* Successfully changed the userName */
    printf("%s\n", CHANGE_PASSWORD_SUCCESS);

    return 0;
}

uint32_t installCustomPBA(struct sedContext *sedCtx, char *drive)
{
    char usbDevice[MAX_PATH_LENGTH] = {0};

    //TODO: Find correct error
    if (drive == NULL)
	return sedError = 1;

    if (selectUsbDevice(usbDevice, sizeof(usbDevice)) == NULL)
        return 1;

    if (mountUSB(usbDevice))
        return sedError = EUSBMOUNT;

    /* Check to see if there is a pba located on the drive */
    if (access(CUSTOM_PBA, F_OK) == -1)
        return sedError = EPBAEXIST;

    /* Install sedTools with new tools */
    if (setupTools(sedCtx, drive, CUSTOM_PBA))
    {
        if (umount(USB_MOUNT_POINT))
            fprintf(stderr, "Warning: Could not unmount device\n");
	
	return sedError;
    }    

    if (umount(USB_MOUNT_POINT))
        fprintf(stderr, "Warning: Could not unmount device\n");

    return 0;
}


int32_t main(int32_t argc, char *argv[])
{
    int32_t c,index;
    uint32_t retVal = 0, createUser = 0, changeName = 0, changePass = 0, delete = 0, test = 0, boot = 0;
    char *hardDrive = NULL, password[MAX_PASSWORD_LENGTH + 1] = {0}, user[MAX_NAME_LENGTH] = {0};
    char newName[MAX_NAME_LENGTH] = {0}, authType[MAX_NAME_LENGTH] = {0};
    uint8_t id = 0;
    struct password_complexity complexity;
    struct sedContext *sedCtx;
    SedAccounts accountType = -1;
    char *pba = NULL, choice = 0;
    opterr = 0;

	if (argc < 3)
	{
		help();
		return 1;
	}

    /* Drive should be the first argument */
    if ((hardDrive = argv[1]) == NULL)
    {
        fprintf(stderr, "%s\n", ERROR_BAD_DRIVE);
        return 1;
    }


    /* Get ctx ready for use */
    if ((sedCtx = (struct sedContext *)malloc(sizeof(struct sedContext))) == NULL)
    {
        fprintf(stderr, "Error: Can not allocate memory for sedCtx\n");
        exit(EXIT_FAILURE);
    }

    /* Initialize Drive */
    if (sed_initialize(sedCtx, hardDrive, User, id))
    {
        fprintf(stderr, "Error: %s\n", getStringError(sedError));
        return 1;
    }

    while ((c = getopt_long(argc, argv, "hvDzsi:r:R:cCluUapPteTo:n:m:A:g:b", longOptions, NULL)) != -1)
    {
        switch(c)
        {
            case 'h':
                help();
                return 0;
            
            case 'v':
                verbose = 1;
                sed_enableVerbose();
                break;
            
            case 'D':
                defaultAccount = 1;
                break;

            case 'z':
                sed_printLevelZeroDiscovery(sedCtx);
                break;

            case 's':
            	retVal = setupTools(sedCtx, hardDrive, pba ? pba : NULL);
                break;

            case 'i':
                pba = optarg;
            	break;

            case 'r':
                if (strlen(optarg) > MAX_PASSWORD_LEN) return EPASSLEN;
                strncpy(password, optarg, sizeof(password));
                retVal = revert(sedCtx, password);
                break;

            case 'R':
                if (strlen(optarg) > MAX_PASSWORD_LEN) return EPASSLEN;
                strncpy(password, optarg, sizeof(password));
                retVal = psidRevert(sedCtx, password);
                break;

            case 'c':
                createUser = 1;
                break;

            case 'C':
                delete = 1;
                break;

            case 'l':
                retVal = lockDrive(sedCtx);
                break;

            case 'u':
                retVal = unlockDrive(sedCtx);
                break;

            case 'U':
                retVal = sed_unshadowDrive(sedCtx);
                break;

            case 'a':
                retVal = listAccounts(sedCtx);
                break;

            case 'p':
                retVal = listComplexity(sedCtx);
                break;

            case 'P':
                if (!promptAdminLogin(sedCtx))
                    configurePasswordRequirements(sedCtx, &complexity, INTERACTIVE);
                break;

            case 'm':
                changeName = 1;
                break;

            case 't':
                changePass = 1;
                break;

            case 'T':
                test = 1;
                break;

            case 'e':
                retVal = secureErase(sedCtx);
                break;

            case 'b':
                boot = 1;
                break;

            case 'o':
                if (strlen(optarg) > MAX_NAME_LENGTH) return ENAMELEN;
                strncpy(user, optarg, sizeof(user));
                break;

            case 'n':
                if (strlen(optarg) > MAX_NAME_LENGTH) return ENAMELEN;
                strncpy(newName, optarg, sizeof(newName));  
                break;

            case 'A':
                if (strlen(optarg) > MAX_NAME_LENGTH) return ENAMELEN;
                strncpy(authType, optarg, sizeof(authType));
                break;

            case 'g':
                accountType =  getSedAccountFromString(optarg);
                break;

            case '?':
                fprintf(stderr, "Unknown Option %c\n", optopt);
				return EXIT_FAILURE;
            
            default:
                help();
                return EXIT_FAILURE;
        }
    }
  
    for (index = optind; index < argc; ++index)
    {
        if (strcmp(argv[index], hardDrive))
            fprintf(stderr, "WARNING: non-option argument %s\n",argv[index]);
    }


    /* User is trying to create user, make sure all parameters are set */
    if (createUser)
    {
        if (authType[0] && accountType != -1 && user[0])
            retVal = createAccount(sedCtx, user, authType, accountType);

        else if (!authType[0] && accountType == -1 && !user[0])
            interactiveCreateUser(sedCtx);

        else
        {
            fprintf(stderr, "\nInvalid options. Did you try\n\t--create-user --user \"newName\" --authtype [password | usb | smartcard | 2password | smartcard+password] --account-type [User | Admin | Distress]\n");
            sedError = EICHOICE;
        }
            
    }
    
    /* User is trying to change userName, make sure all parameters are set */
    if (changeName)
    {
        if (newName[0] && user[0])
            retVal = promptChangeUsername(sedCtx, user, newName);

        else if (!newName[0] && !user[0])
            interactiveChangeUsername(sedCtx);

        else
        {
            fprintf(stderr, "\nInvalid options. Did you try\n\t--change-username --user \"oldName\" --newname \"newName\"\n");
            sedError = EICHOICE;
        }       
    }

    /* User is trying to change password */
    if (changePass)
    {
        if (authType[0] && user[0])
            promptChangePassword(sedCtx, user, authType);

        else if (!authType[0] && !user[0])
            interactiveChangePassword(sedCtx);

        else
        {
            fprintf(stderr, "\nInvalid options. Did you try\n\t--change-password --user \"user\" --authtype [password | usb | smartcard | 2password | smartcard+password]\n");
            sedError = EICHOICE; 
        }
    }

    if (delete)
    {
        if (user[0])
            deleteAccount(sedCtx, user);

        else if (!user[0])
            interactiveDeleteUser(sedCtx);

        else
        {
            fprintf(stderr, "\nInvalid options. Did you try\n\t--delete-user --user \"user\"\n");
            sedError = EICHOICE; 
        }
    }

    if (test)
    {
        if (defaultAccount)
            testLogin(sedCtx, NULL);
        else if (user[0])
            testLogin(sedCtx, user);
        else
        {
            fprintf(stderr, "\nInvalid options. Did you try\n\t--test-login --user \"user\"\n");
            sedError = EICHOICE; 
        }

    }

    if (boot)
    {
        if (!sed_isOwned(sedCtx, hardDrive)) 
        {
            displayTitle("Self-encrypting Drive Management Tools", 1);
            printf("Self-encrypting Drive Management Tools are not installed on this Device.\n");
            printf("Do you want to install the management tools? [y/n]\n");

            choice = getMenuChoice();

            if (choice == 'y' || choice == 'Y')
            {
                system("clear");
                printf("Please select which PBA you would like to install.\n");
                printf("1) Default PBA\n2) Custom PBA via USB device");

                choice = getMenuChoice();

                if (choice == '1')
                    retVal = setupTools(sedCtx, hardDrive, DEFAULT_PBA);
                    
                else if (choice == '2')
                    retVal = installCustomPBA(sedCtx, hardDrive);

                else
                {
                    fprintf(stderr, "Invalid Choice. Rebooting ...\n");
                    system("reboot -f 2>/dev/null");
                }
            }
                
            else
            {
                printf("\n\nThe Self-encrypting Drive Management Tools will not be installed. Press Any Key to Continue ...\n");
                getMenuChoice();
                system("reboot -f 2>/dev/null");
            }
        }

        else
            retVal = bootPBA(sedCtx);
    }
        
    sed_cleanup(sedCtx);

    if (sedError)
    {
        fprintf(stderr, "\nError: %s\n", getStringError(sedError));
        sleep(DELAY);
        system("reboot -f 2>/dev/null");
    }

    return retVal;
}
