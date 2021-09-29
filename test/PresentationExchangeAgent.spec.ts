import { PresentationDefinition } from '@sphereon/pe-models';

import { PresentationExchangeAgent } from '../src/PresentationExchangeAgent';

describe("presentation exchange agent tests", () => {
  it("pass if no PresentationDefinition is found", async () => {
    const peAgent: PresentationExchangeAgent = new PresentationExchangeAgent();
    const pd: PresentationDefinition = peAgent.findValidPresentationDefinition({ url: "http://localhost:8080"});
    expect(pd).toBeNull();
  });

  it("pass if findValidPresentationDefinition finds a valid presentation_definition", async () => {
    const peAgent: PresentationExchangeAgent = new PresentationExchangeAgent();
    const obj = {
      'id_token': {
        'acr': null,
        'verifiable_presentations': {
          'presentation_definition': {
            'id': 'Health Insurance Plan',
            'input_descriptors': [
              {
                'id': 'Ontario Health Insurance Plan',
                'schema': [
                  {
                    'uri': 'https://did.itsourweb.org:3000/smartcredential/Ontario-Health-Insurance-Plan'
                  }
                ]
              }
            ]
          }
        }
      }
    };
    const pd = peAgent.findValidPresentationDefinition(obj);
    expect(pd["id"]).toBe("Health Insurance Plan");
    expect(pd["input_descriptors"][0].schema.length).toBe(1);
  });
});
