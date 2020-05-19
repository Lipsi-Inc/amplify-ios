//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify

// swiftlint:disable:next type_name
public class AWSAuthAttributeResendConfirmationCodeOperation: AmplifyOperation<
    AuthAttributeResendConfirmationCodeRequest,
    AuthCodeDeliveryDetails,
    AuthError
>, AuthAttributeResendConfirmationCodeOperation {

    let userService: AuthUserServiceBehavior

    init(_ request: AuthAttributeResendConfirmationCodeRequest,
         userService: AuthUserServiceBehavior,
         resultListener: ResultListener?) {

        self.userService = userService
        super.init(categoryType: .auth,
                   eventName: HubPayload.EventName.Auth.attributeResendConfirmationCode,
                   request: request,
                   resultListener: resultListener)
    }

    override public func main() {
        if isCancelled {
            finish()
            return
        }
        userService.resendAttributeConfirmationCode(request: request) { [weak self] result in
            guard let self = self else { return }
            defer {
                self.finish()
            }
            switch result {
            case .failure(let error):
                self.dispatch(error)
            case .success(let result):
                self.dispatch(result)
            }
        }
    }

    private func dispatch(_ result: AuthCodeDeliveryDetails) {
        let result = OperationResult.success(result)
        dispatch(result: result)
    }

    private func dispatch(_ error: AuthError) {
        let result = OperationResult.failure(error)
        dispatch(result: result)
    }
}