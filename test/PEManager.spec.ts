import { PresentationDefinition } from '@sphereon/pe-models';

import { PEManager } from '../src';

describe("presentation exchange manager tests", () => {
  it("pass if no PresentationDefinition is found", async () => {
    const peManager: PEManager = new PEManager();
    const pd: PresentationDefinition = peManager.findValidPresentationDefinition({ url: "http://localhost:8080"});
    expect(pd).toBeNull();
  });

  it("pass if findValidPresentationDefinition finds a valid presentation_definition", async () => {
    const peManager: PEManager = new PEManager();
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
    const pd = peManager.findValidPresentationDefinition(obj);
    expect(pd["id"]).toBe("Health Insurance Plan");
    expect(pd["input_descriptors"][0].schema.length).toBe(1);
  });
});
