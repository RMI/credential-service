/* generated using openapi-typescript-codegen -- do no edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CredentialCheck } from '../models/CredentialCheck';
import type { Error } from '../models/Error';

import type { CancelablePromise } from '../core/CancelablePromise';
import type { BaseHttpRequest } from '../core/BaseHttpRequest';

export class DefaultService {

    constructor(public readonly httpRequest: BaseHttpRequest) {}

    /**
     * Confirm that a given JWT can be used with RMI srevices.
     * Takes in a RMI JWT token and confirms that it meets all the requirements
     * of a valid token (e.g. valid signature, not expired, etc).
     *
     * Note that even when this endpoint fails, it returns a 200 response. The
     * response body will contain the reason for the failure.
     *
     * @returns CredentialCheck API key response
     * @returns Error unexpected error
     * @throws ApiError
     */
    public checkCredentials(): CancelablePromise<CredentialCheck | Error> {
        return this.httpRequest.request({
            method: 'POST',
            url: '/credentials:check',
        });
    }

}
