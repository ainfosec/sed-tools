#include "../include/menu/adminMenu.h"

void displayAdminMenu(struct sedContext *sedCtx)
{
	char choice;
    sedError = 0;

    displayTitle(ADMIN_MENU_TITLE, 1);

	printf("1) "MANAGE_ACCOUNT"\n2) "SECURE_ERASE"\n3) "REVERT_DRIVE"\n4) "BOOT_DRIVE"\n");

	switch ((choice = getMenuChoice()))
    {
        case '1':
            displayAccountOptions(sedCtx);
            break;
    
        case '2':
            menu_secureErase(sedCtx);
            break;
    
        case '3':
            revertDrive(sedCtx);
            break;
    
        case '4':
            bootDrive(sedCtx);
            break;
    
        default:
            menu_printMessage(sedCtx, ERROR_INVALID_CHOICE);   
    }
}
  
void displayAccountOptions(struct sedContext *sedCtx)
{
	char choice;
    sedError = 0;

    displayTitle(USER_MENU_TITLE, 1);

	printf("1) "CREATE_USER"\n2) "CHANGE_USERNAME"\n3) "CHANGE_PASSWORD"\n4) "DELETE_USER"\n"
           "5) "LIST_USERS"\n6) "CONFIGURE_COMPLEXITY"\n7) "ADMIN_MENU_TITLE"\n");

	switch ((choice = getMenuChoice()))
    {    
        case '1':
            menu_createUser(sedCtx);
            break;
        
        case '2':
            menu_changeUserName(sedCtx);
            break;
    
        case '3':
            menu_changePassword(sedCtx);
            break;
    
        case '4':
            menu_deleteUser(sedCtx);
            break;

        case '5':
            listAllUserInfo(sedCtx);
            break;

        case '6':
            passwordComplexity(sedCtx);
            break;
        
        case '7':
            displayAdminMenu(sedCtx);
            break;

        default:
            printf("%s\n", ERROR_INVALID_CHOICE);
            displayAccountOptions(sedCtx);
    }
}

void menu_createUser(struct sedContext *sedCtx)
{
    struct userInfo user;

    system("clear");
    
    /* Get the new username */  
    if (promptNewUsername(sedCtx, &user))
        menu_displayError(sedCtx, sedError);

    /* Get Account Type */
    if (promptNewAccountType(sedCtx, &user))
        menu_displayError(sedCtx, sedError);

    /* Get next available id */
    user.id = getNextAvailableID(sedCtx, user.accountType);
    if (sedError)
        menu_displayError(sedCtx, sedError);

    /* Get Authentication Type */
    if (promptNewAuthType(sedCtx, &user))
        menu_displayError(sedCtx, sedError);

    /* Create user with gathered credentials */
    if (createUser(sedCtx, user))
        menu_displayError(sedCtx, sedError);

    /* Successfully created new user */
    menu_printMessage(sedCtx, "Successfully created User");
    
    displayAccountOptions(sedCtx);
}

void menu_secureErase(struct sedContext *sedCtx)
{
    char choice; 

    system("clear");
    
    printf("%s\n", INITIATE_ERASE);
    printf("%s\n", ERASE_WARNING);
    printf("\n%s", CONTINUE_CHOICE);

    /* Make sure the user really wants to erase the drive */
    choice = getMenuChoice();

    /* If the user does not want to erase the drive, then go back to admin menu */
    if (choice == 'n' || choice == 'N')
        displayAdminMenu(sedCtx);

    /* Continue with erasing the drive */
    else if (choice == 'y' || choice == 'Y')
    {
        /* Erase range number 1 since we only support one range */
        if (lockingRange_erase(sedCtx, LOCKING_RANGE_1) & SED_ERROR)    
            menu_displayError(sedCtx, EERASE);
   
        menu_printMessage(sedCtx, ERASE_SUCCESS); 
    }
    
    /* The user typed in an invalid response */
    else
        menu_displayError(sedCtx, EICHOICE);  
}
    
void revertDrive(struct sedContext *sedCtx)
{
    char password[MAX_PASSWORD_LENGTH] = {0};

    system("clear");
    
    printf("%s\n", INITIATE_REVERT);
    printf("%s\n\n", REVERT_WARNING);

    if (promptPassword("Enter Distress password:", password, MAX_PASSWORD_LENGTH) == NULL)
        menu_displayError(sedCtx, EICREDS);

    if (sed_revertDrive(sedCtx, password))
        menu_displayError(sedCtx, sedError);

    /* Drive successfully reverted, now reboot */
    printf("%s \n",REVERT_SUCCESS);
    sleep(DELAY);
    
    system("reboot -f 2>/dev/null");
    exit(EXIT_SUCCESS); 
}

void menu_changeUserName(struct sedContext *sedCtx)
{
    char newName[MAX_NAME_LENGTH] = {0}, oldName[MAX_NAME_LENGTH] = {0};
    
    system("clear");

    /* Choose which user account name to change */
    if (selectUserFromList(sedCtx, oldName, sizeof(oldName)) == NULL)
        displayAccountOptions(sedCtx);

    /* Get the new userName */  
    printf("\n%s", PROMPT_USERNAME);
    
    if (readInput(newName, MAX_NAME_LENGTH) == NULL)
        menu_displayError(sedCtx, ECHNGNME);

    /* Update the userName with the new name */
    if (changeUserName(sedCtx, oldName, newName))
        menu_displayError(sedCtx, sedError);

    /* Successfully changed the userName */
    menu_printMessage(sedCtx, CHANGE_NAME_SUCCESS);
}

void menu_changePassword(struct sedContext *sedCtx)
{
    char choice;
    struct userInfo user;
    
    system("clear");

    printf("Select the Account Type: \n\n1) User Accounts\n2) Distress Account\n");
    choice = getMenuChoice();

    if (choice == '2')
    {
        setDistressPassword(sedCtx);
        displayAccountOptions(sedCtx);
    }

    /* Choose which user account to change the password for and gather its information */
    if (selectUserFromList(sedCtx, *(&user.userName), sizeof(user.userName)) == NULL)
        displayAccountOptions(sedCtx);

    if (getUserInformationFromUserName(sedCtx, &user))
        menu_displayError(sedCtx, sedError);

    // TODO: Add smartcard and smartcard + password once smartcard support is updated
    /* Allow the user to select the new authentication type */
    printf("%s\n\n", AUTH_CHOICE);
    printf("1) Password\n2) USB\n3) Two Passwords\n"); 
    choice = getMenuChoice();

    system("clear");

    user.authenticationType = choice;

    if (setupNewAuth(sedCtx, user))
        menu_displayError(sedCtx, sedError);

    menu_printMessage(sedCtx, PASSWORD_CHANGE_SUCCESS);
}

void menu_deleteUser(struct sedContext *sedCtx)
{
    char user[MAX_NAME_LENGTH] = {0};

    system("clear");
 
    /* Choose a user whose account is to be deleted */
    if (selectUserFromList(sedCtx, user, sizeof(user)) == NULL)
        displayAccountOptions(sedCtx);

    /* Get All info about user */
    if (deleteUser(sedCtx, user))
        menu_displayError(sedCtx, sedError);

    /* Successfully deleted the user */
    menu_printMessage(sedCtx, DELETE_USER_SUCCESS);
}

void listAllUserInfo(struct sedContext *sedCtx)
{
    displayTitle(CURRENT_USER_ACCOUNTS, 1);
    
    /* Display all of the current users on the drive */
    if (listNormalAccounts(sedCtx))
        menu_displayError(sedCtx, sedError);

    /* Inform about the number of available slots for the user account */
    printf("\n%s%d\n\n\n", NUMBER_OF_AVAIL_SLOTS_USER, MAX_USERS - getUserCount(sedCtx));

    /* Print out a pretty title line for the admin information */
    displayTitle(CURRENT_ADMINS, 0);

    /* Display all of current Admins on the drive */
    if (listAdminAccounts(sedCtx))
        menu_displayError(sedCtx, sedError);

    /* Inform about the number of available slots for the Admin account */
    printf("\n%s%d\n\n", NUMBER_OF_AVAIL_SLOTS_ADMIN, MAX_ADMINS - getAdminCount(sedCtx));
    
    /* Press any key to continue */
    printf("%s", PRESS_ANY_KEY);   
    getMenuChoice();
    
    displayAccountOptions(sedCtx);
}

void passwordComplexity(struct sedContext *sedCtx)
{
    struct password_complexity complexity;
    char choice;

    /* Get the current password complexity rules */
    if (getPasswordRequirements(sedCtx, &complexity))
        displayAccountOptions(sedCtx);

    displayTitle(CURRENT_COMPLEXITY_CONFIGURATION, 1);

    /* Display the complexity */
    displayPasswordComplexity(sedCtx, &complexity);
   
    /* Give the user the option to either keep the current configuration or modify it */
    printf("%s", KEEP_MOIDFY_CONFIGURATION);
    choice = getMenuChoice();

    /* Modify the current configuration */
    if (choice == 'm' || choice == 'M')
        modifyPasswordComplexity(sedCtx);

    /* Keep the current configuration */
    else if (choice == 'k' || choice == 'K')
        displayAccountOptions(sedCtx);

    /* The user entered an invalid choice */
    else
        menu_displayError(sedCtx, EICHOICE);
}

void modifyPasswordComplexity(struct sedContext *sedCtx)
{
    struct password_complexity complexity;

    system("clear");

    /* Get the current password complexity rules */
    if (getPasswordRequirements(sedCtx, &complexity))
        displayAccountOptions(sedCtx);
    
    /* Configure the new complexity */
    if (configurePasswordRequirements(sedCtx, &complexity, 1))
        displayAccountOptions(sedCtx);

    displayTitle(NEW_COMPLEXITY_CONFIGURATION, 1);

    /* Display the complexity */
    displayPasswordComplexity(sedCtx, &complexity);

    printf("%s", PRESS_ANY_KEY);

    getMenuChoice();
    displayAccountOptions(sedCtx);
}

void menu_displayError(struct sedContext *sedCtx, uint32_t errorNum)
{   
    fprintf(stderr, "\nError: %s\n", getStringError(errorNum));
    sleep(DELAY);
    displayAdminMenu(sedCtx);
}

void menu_printMessage(struct sedContext *sedCtx, char *message)
{
    printf("\n%s\n",message);
    sleep(DELAY);
    displayAdminMenu(sedCtx);
}
