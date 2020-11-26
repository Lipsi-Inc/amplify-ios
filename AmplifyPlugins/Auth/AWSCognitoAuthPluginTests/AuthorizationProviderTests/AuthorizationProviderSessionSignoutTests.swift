//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

import XCTest
@testable import Amplify
@testable import AWSCognitoAuthPlugin
@testable import AWSMobileClient
import AWSPluginsCore

class AuthorizationProviderSessionSignoutTests: BaseAuthorizationProviderTest {

    override func setUp() {
        super.setUp()
        mockAWSMobileClient.mockCurrentUserState = .guest
    }

    func testSignoutSessionWithUnAuthAccess() {

        let mockAWSCredentials = AWSCredentials(accessKey: "mockAccess",
                                                secretKey: "mockSecret",
                                                sessionKey: "mockSession",
                                                expiration: Date())
        mockAWSMobileClient.awsCredentialsMockResult = .success(mockAWSCredentials)
        mockAWSMobileClient.getIdentityIdMockResult = AWSTask(result: "mockIdentityId")

        let resultExpectation = expectation(description: "Should receive a result")
        _ = plugin.fetchAuthSession(options: AuthFetchSessionRequest.Options()) { result in
            defer {
                resultExpectation.fulfill()
            }
            switch result {
            case .success(let session):

                XCTAssertFalse(session.isSignedIn)

                let creds = try? (session as? AuthAWSCredentialsProvider)?.getAWSCredentials().get()
                XCTAssertNotNil(creds?.accessKey)
                XCTAssertNotNil(creds?.secretKey)

                let identityId = try? (session as? AuthCognitoIdentityProvider)?.getIdentityId().get()
                XCTAssertNotNil(identityId)

                let tokensResult = (session as? AuthCognitoTokensProvider)?.getCognitoTokens()
                guard case .failure(let error) = tokensResult,
                      case .signedOut = error else {
                    XCTFail("Should return signedOut error")
                    return
                }

            case .failure(let error):
                XCTFail("Received failure with error \(error)")
            }
        }
        wait(for: [resultExpectation], timeout: apiTimeout)
    }

    func testInvalidCredentialsResponseInSignedOut() {

        mockAWSMobileClient.awsCredentialsMockResult = nil
        mockAWSMobileClient.getIdentityIdMockResult = AWSTask(result: "mockIdentityId")

        let resultExpectation = expectation(description: "Should receive a result")
        _ = plugin.fetchAuthSession(options: AuthFetchSessionRequest.Options()) { result in
            defer {
                resultExpectation.fulfill()
            }
            switch result {
            case .success(let session):
                XCTAssertFalse(session.isSignedIn)

                XCTAssertFalse(session.isSignedIn)

                let credentialsResult = (session as? AuthAWSCredentialsProvider)?.getAWSCredentials()
                guard case .failure(let credentialsError) = credentialsResult,
                      case .unknown = credentialsError else {
                    XCTFail("Should return unknown error")
                    return
                }

                let identityIdResult = (session as? AuthCognitoIdentityProvider)?.getIdentityId()
                guard case .failure(let identityIdError) = identityIdResult,
                      case .unknown = identityIdError else {
                    XCTFail("Should return unknown error")
                    return
                }

                let tokensResult = (session as? AuthCognitoTokensProvider)?.getCognitoTokens()
                guard case .failure(let error) = tokensResult,
                      case .signedOut = error else {
                    XCTFail("Should return signedOut error")
                    return
                }
            case .failure(let error):
                XCTFail("Received failure with error \(error)")
            }
        }
        wait(for: [resultExpectation], timeout: apiTimeout)
    }

    func testInvalidIdentityIdResponseInSignedOut() {

        let mockAWSCredentials = AWSCredentials(accessKey: "mockAccess",
                                                secretKey: "mockSecret",
                                                sessionKey: "mockSession",
                                                expiration: Date())
        mockAWSMobileClient.awsCredentialsMockResult = .success(mockAWSCredentials)
        mockAWSMobileClient.getIdentityIdMockResult = AWSTask(result: nil)

        let resultExpectation = expectation(description: "Should receive a result")
        _ = plugin.fetchAuthSession(options: AuthFetchSessionRequest.Options()) { result in
            defer {
                resultExpectation.fulfill()
            }
            switch result {
            case .success(let session):
                XCTAssertFalse(session.isSignedIn)

                XCTAssertFalse(session.isSignedIn)

                let credentialsResult = (session as? AuthAWSCredentialsProvider)?.getAWSCredentials()
                guard case .failure(let credentialsError) = credentialsResult,
                      case .unknown = credentialsError else {
                    XCTFail("Should return unknown error")
                    return
                }

                let identityIdResult = (session as? AuthCognitoIdentityProvider)?.getIdentityId()
                guard case .failure(let identityIdError) = identityIdResult,
                      case .unknown = identityIdError else {
                    XCTFail("Should return unknown error")
                    return
                }

                let tokensResult = (session as? AuthCognitoTokensProvider)?.getCognitoTokens()
                guard case .failure(let error) = tokensResult,
                      case .signedOut = error else {
                    XCTFail("Should return signedOut error")
                    return
                }
            case .failure(let error):
                XCTFail("Received failure with error \(error)")
            }
        }
        wait(for: [resultExpectation], timeout: apiTimeout)
    }
}
