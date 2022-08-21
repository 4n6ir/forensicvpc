#!/usr/bin/env python3
import os

import aws_cdk as cdk

from forensicvpc.forensicvpc_stack import ForensicvpcStack

app = cdk.App()

ForensicvpcStack(
    app, 'ForensicvpcStack',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = os.getenv('CDK_DEFAULT_REGION')
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

cdk.Tags.of(app).add('forensicvpc','forensicvpc')

app.synth()
