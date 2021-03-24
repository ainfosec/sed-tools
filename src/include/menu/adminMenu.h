#ifndef __ADMINMENU_H_
#define __ADMINMENU_H_


#include <stdio.h>
#include <stdint.h>
#include "../password/sedAuth.h"
#include "../sed/sed.h"

void menu_displayError(struct sedContext *sedCtx, uint32_t errorNum);
/*
    @description: Displays the admin Menu

    @parameter sedCtx    - Sed context struct

    @return - Nothing
*/
void displayAdminMenu(struct sedContext *sedCtx);

/*
    @description: Displays the account Management options

    @parameter sedCtx     - Sed context struct

    @return - Nothing
*/
void displayAccountOptions(struct sedContext *sedCtx);

/*
    @description: Erases all of the data on the drive except the Opal stuff. (users, and passwords)

    @parameter sedCtx      - Sed context struct

    @return - Nothing
*/
void menu_secureErase(struct sedContext *sedCtx);

/*
    @description: Completely erases everything off of the drive. Restores the drive back to the manufactured state

    @parameter sedCtx      	- Sed context struct

    @return - Nothing
*/
void revertDrive(struct sedContext *sedCtx);

/*
    @description: Allows you to change a username from a list of users that currently exist on the system

    @parameter sedCtx    - Sed context struct

    @return - Nothing
*/
void menu_changeUserName(struct sedContext *sedCtx);

/*
    @description: Allows you to change the password and/or the authentication type of a user from a list of users

    @parameter sedCtx    - Sed context struct

    @return - Nothing
*/
void menu_changePassword(struct sedContext *sedCtx);

/*
    @description: Allows you to delete an account from a list of users

    @parameter sedCtx   - Sed context struct

    @return - Nothing
*/
void menu_deleteUser(struct sedContext *sedCtx);

/*
    @description: List all of the current User accounts and Admin accounts and the number of free slots available for each account type

    @parameter sedCtx   - Sed context struct

    @return - Nothing
*/
void listAllUserInfo(struct sedContext *sedCtx);

/*
    @description: Displays tthe current password Complexity and give the option to keep it or modify it

    @parameter sedCtx   - Sed context struct

    @return - Nothing
*/
void passwordComplexity(struct sedContext *sedCtx);

void modifyPasswordComplexity(struct sedContext *sedCtx);
void menu_createUser(struct sedContext *sedCtx);
void menu_printMessage(struct sedContext *sedCtx, char *message);

#endif /*__ADMINMENU_H_ */
