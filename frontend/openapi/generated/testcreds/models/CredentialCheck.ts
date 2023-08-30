/* generated using openapi-typescript-codegen -- do no edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */

export type CredentialCheck = {
    /**
     * Whether or not the token was valid
     */
    valid: boolean;
    /**
     * Description of why the token was invalid, only populated if valid is false.
     */
    failureReason?: string;
    /**
     * Unique identifier for the token, only populated if valid is true.
     */
    tokenID?: string;
    /**
     * Identifier for the user, only populated if valid is true.
     */
    userID?: string;
};

