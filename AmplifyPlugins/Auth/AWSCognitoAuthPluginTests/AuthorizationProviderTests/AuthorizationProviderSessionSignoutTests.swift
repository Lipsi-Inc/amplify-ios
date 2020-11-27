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

    /// Test signedOut session with unAuthenticated access enabled.
    ///
    /// - Given: Given an auth plugin with signedOut state and unauthenticated access enabled in backend
    /// - When:
    ///    - I invoke fetchAuthSession
    /// - Then:
    ///    - I should get an a valid session with the following details:
    ///         - isSignedIn = false
    ///         - aws credentails = valid values
    ///         - identity id = valid values
    ///         - cognito tokens = .signedOut error
    ///
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

    /// Test signedOut session with unAuthenticated access disabled.
    ///
    /// - Given: Given an auth plugin with signedOut state and unauthenticated access disabled in backend
    /// - When:
    ///    - I invoke fetchAuthSession and mock disabled guest in service
    /// - Then:
    ///    - I should get an a valid session with the following details:
    ///         - isSignedIn = false
    ///         - aws credentails = .service error with .invalidAccountTypeException as underlying error
    ///         - identity id = .service error with .invalidAccountTypeException as underlying error
    ///         - cognito tokens = .signedOut error
    func testSignoutSessionWithUnAuthAccessDisabled() {

        let mockNoGuestError = AWSMobileClientError.guestAccessNotAllowed(message: "Error")
        mockAWSMobileClient.awsCredentialsMockResult = .failure(mockNoGuestError)
        mockAWSMobileClient.getIdentityIdMockResult = AWSTask(result: "mockIdentityId")

        let resultExpectation = expectation(description: "Should receive a result")
        _ = plugin.fetchAuthSession(options: AuthFetchSessionRequest.Options()) { result in
            defer {
                resultExpectation.fulfill()
            }
            switch result {
            case .success(let session):
                XCTAssertFalse(session.isSignedIn)

                let credentialsResult = (session as? AuthAWSCredentialsProvider)?.getAWSCredentials()
                guard case .failure(let credentialsError) = credentialsResult,
                      case .service(_, _, let underlyingError) = credentialsError,
                      case .invalidAccountTypeException = (underlyingError as? AWSCognitoAuthError) else {
                    XCTFail("Should return network error")
                    return
                }

                let identityIdResult = (session as? AuthCognitoIdentityProvider)?.getIdentityId()
                guard case .failure(let identityIdError) = identityIdResult,
                      case .service(_, _, let identityIdUnderlyingError) = identityIdError,
                      case .invalidAccountTypeException = (identityIdUnderlyingError as? AWSCognitoAuthError) else {
                    XCTFail("Should return network error")
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

    /// Test signedOut session with a invalid response for AWS Credentials
    ///
    /// - Given: Given an auth plugin with signedOut state and unauthenticated access enabled in backend
    /// - When:
    ///    - I invoke fetchAuthSession and mock invalid response for aws credentials
    /// - Then:
    ///    - I should get an a valid session with the following details:
    ///         - isSignedIn = false
    ///         - aws credentails = .unknown error
    ///         - identity id = .unknown error
    ///         - cognito tokens = .signedOut error
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

    /// Test signedOut session with a invalid response for AWS Credentials
    ///
    /// - Given: Given an auth plugin with signedOut state and unauthenticated access enabled in backend
    /// - When:
    ///    - I invoke fetchAuthSession and mock invalid response for identity id
    /// - Then:
    ///    - I should get an a valid session with the following details:
    ///         - isSignedIn = false
    ///         - aws credentails = .unknown error
    ///         - identity id = .unknown error
    ///         - cognito tokens = .signedOut error
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

    /// Test signedOut session with a network error
    ///
    /// - Given: Given an auth plugin with signedOut state and unauthenticated access enabled in backend
    /// - When:
    ///    - I invoke fetchAuthSession and mock URL domain error for get aws credentials
    /// - Then:
    ///    - I should get an a valid session with the following details:
    ///         - isSignedIn = false
    ///         - aws credentails = .service error with .network as underlying error
    ///         - identity id = .service error with .network as underlying error
    ///         - cognito tokens = .signedOut error
    func testNetworkErrorForIdentityIdInSignedOut() {

        let error = NSError(domain: NSURLErrorDomain, code: 1, userInfo: nil)
        let mockAWSCredentials = AWSCredentials(accessKey: "mockAccess",
                                                secretKey: "mockSecret",
                                                sessionKey: "mockSession",
                                                expiration: Date())
        mockAWSMobileClient.awsCredentialsMockResult = .success(mockAWSCredentials)
        mockAWSMobileClient.getIdentityIdMockResult = AWSTask(error: error)

        let resultExpectation = expectation(description: "Should receive a result")
        _ = plugin.fetchAuthSession(options: AuthFetchSessionRequest.Options()) { result in
            defer {
                resultExpectation.fulfill()
            }
            switch result {
            case .success(let session):
                XCTAssertFalse(session.isSignedIn)

                let credentialsResult = (session as? AuthAWSCredentialsProvider)?.getAWSCredentials()
                guard case .failure(let credentialsError) = credentialsResult,
                      case .service(_, _, let underlyingError) = credentialsError,
                      case .network = (underlyingError as? AWSCognitoAuthError) else {
                    XCTFail("Should return network error")
                    return
                }

                let identityIdResult = (session as? AuthCognitoIdentityProvider)?.getIdentityId()
                guard case .failure(let identityIdError) = identityIdResult,
                      case .service(_, _, let identityIdUnderlyingError) = identityIdError,
                      case .network = (identityIdUnderlyingError as? AWSCognitoAuthError) else {
                    XCTFail("Should return network error")
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

    /// Test signedOut session with a network error
    ///
    /// - Given: Given an auth plugin with signedOut state and unauthenticated access enabled in backend
    /// - When:
    ///    - I invoke fetchAuthSession and mock URL domain error for getIdentityId
    /// - Then:
    ///    - I should get an a valid session with the following details:
    ///         - isSignedIn = false
    ///         - aws credentails = .service error with .network as underlying error
    ///         - identity id = .service error with .network as underlying error
    ///         - cognito tokens = .signedOut error
    func testNetworkErrorForAWSCredentialsInSignedOut() {

        let error = NSError(domain: NSURLErrorDomain, code: 1, userInfo: nil)
        mockAWSMobileClient.awsCredentialsMockResult = .failure(error)
        mockAWSMobileClient.getIdentityIdMockResult = AWSTask(result: "mockIdentityId")

        let resultExpectation = expectation(description: "Should receive a result")
        _ = plugin.fetchAuthSession(options: AuthFetchSessionRequest.Options()) { result in
            defer {
                resultExpectation.fulfill()
            }
            switch result {
            case .success(let session):
                XCTAssertFalse(session.isSignedIn)

                let credentialsResult = (session as? AuthAWSCredentialsProvider)?.getAWSCredentials()
                guard case .failure(let credentialsError) = credentialsResult,
                      case .service(_, _, let underlyingError) = credentialsError,
                      case .network = (underlyingError as? AWSCognitoAuthError) else {
                    XCTFail("Should return network error")
                    return
                }

                let identityIdResult = (session as? AuthCognitoIdentityProvider)?.getIdentityId()
                guard case .failure(let identityIdError) = identityIdResult,
                      case .service(_, _, let identityIdUnderlyingError) = identityIdError,
                      case .network = (identityIdUnderlyingError as? AWSCognitoAuthError) else {
                    XCTFail("Should return network error")
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
