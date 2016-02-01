
package okta.mvc;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

 
@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
 
     
    // Initialization of the velocity engine
    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }
 
    // Initialization of OpenSAML library
    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap();
    }
    
    // XML parser pool needed for OpenSAML parsing
    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }
    
    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }
    
    @Bean
    public HTTPSOAP11Binding soapBinding() {
        return new HTTPSOAP11Binding(parserPool());
    }
    
    @Bean
    public HTTPSOAP11Binding paosBinding() {
        return new HTTPPAOS11Binding(parserPool());
    }

    @Bean
    public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
    }
    
    // Bindings
    private ArtifactResolutionProfile artifactResolutionProfile() {
        final ArtifactResolutionProfileImpl artifactResolutionProfile = 
        		new ArtifactResolutionProfileImpl(httpClient());
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
        return artifactResolutionProfile;
    }
    
    @Bean
    public HttpClient httpClient() {
        return new HttpClient(multiThreadedHttpConnectionManager());
    }
    
    // Bindings, encoders and decoders used for creating and parsing messages
    @Bean
    public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }
    
    @Bean
    public HTTPRedirectDeflateBinding redirectBinding() {
    	return new HTTPRedirectDeflateBinding(parserPool());
    }

    @Bean
    public HTTPPostBinding postBinding() {
    	return new HTTPPostBinding(parserPool(), velocityEngine());
    }
    
	//SAML 2.0 Logout Profile
    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }    
    
    // SAML 2.0 ECP profile
    @Bean
    public WebSSOProfileECPImpl ecpprofile() {
        return new WebSSOProfileECPImpl();
    }
    
    // SAML 2.0 Holder-of-Key Web SSO profile 
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }
    
    // SAML 2.0 Web SSO profile
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }
    
    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // SAML 2.0 WebSSO Assertion Consumer
    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }
    
    // Processor
    //Class loading incoming SAML messages from httpRequest stream
	@Bean
	public SAMLProcessorImpl processor() {
		Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
		bindings.add(redirectBinding());
		bindings.add(postBinding());
		bindings.add(artifactBinding(parserPool(), velocityEngine()));
		bindings.add(soapBinding());
		bindings.add(paosBinding());
		return new SAMLProcessorImpl(bindings);
	}

    // Filter processing incoming logout messages
    // First argument determines URL user will be redirected to after successful
    // global logout
    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(),
                logoutHandler());
    }
    
    // Logout handler terminating local session
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = 
        		new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        //logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }
    
    // Handler for successful logout
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl("/");
        return successLogoutHandler;
    }
    
    // Overrides default logout processing filter with the one processing SAML
    // messages
    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[] { logoutHandler() },
                new LogoutHandler[] { logoutHandler() });
    }

    // Handler deciding where to redirect user after successful login
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/");
        return successRedirectHandler;
    }
    
	// Handler deciding where to redirect user after failed login
    @Bean
    public SimpleUrlAuthenticationFailureHandler failureRedirectHandler() {
    	SimpleUrlAuthenticationFailureHandler failureHandler =
    			new SimpleUrlAuthenticationFailureHandler();
    	failureHandler.setUseForward(true);
    	failureHandler.setDefaultFailureUrl("/");
    	return failureHandler;
    }

    // SAML Authentication Provider responsible for validating of received SAML
    // messages
    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        //samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
        //samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }
    
    // Provider of default SAML Context
    @Bean
    public SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl();
    }
    
    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do no forget to call iniitalize method on providers
    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
        providers.add(ssoCircleExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }
    
	@Bean
	@Qualifier("idp-ssocircle")
	public ExtendedMetadataDelegate ssoCircleExtendedMetadataProvider()
			throws MetadataProviderException {
//		String idpSSOCircleMetadataURL = "https://idp.ssocircle.com/idp-meta.xml";
		String idpSSOCircleMetadataURL = "https://dev-771949.oktapreview.com/app/exk5nujgjzgEaB9BB0h7/sso/saml/metadata";
		Timer backgroundTaskTimer = new Timer(true);
		HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(
				backgroundTaskTimer, httpClient(), idpSSOCircleMetadataURL);
		httpMetadataProvider.setParserPool(parserPool());
		ExtendedMetadataDelegate extendedMetadataDelegate = 
				new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata());
		extendedMetadataDelegate.setMetadataTrustCheck(true);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		return extendedMetadataDelegate;
	}

	   // Setup advanced info about metadata
    @Bean
    public ExtendedMetadata extendedMetadata() {
    	ExtendedMetadata extendedMetadata = new ExtendedMetadata();
    	extendedMetadata.setIdpDiscoveryEnabled(true); 
    	extendedMetadata.setSignMetadata(false);
    	return extendedMetadata;
    }

    // Entry point to initialize authentication, default values taken from
    // properties file
    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }
    
    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }
    
    // IDP Discovery Service
    @Bean
    public SAMLDiscovery samlIDPDiscovery() {
        SAMLDiscovery idpDiscovery = new SAMLDiscovery();
        idpDiscovery.setIdpSelectionPath("/login");
        return idpDiscovery;
    }    

    
    // Logger for SAML messages and events
    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }
    
    // Central storage of cryptographic keys
    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader
                .getResource("classpath:/security/samlKeystore.jks");
        String storePass = "nalle123";
        Map<String, String> passwords = new HashMap<String, String>();
        passwords.put("apollo", "nalle123");
        String defaultKey = "apollo";
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }
    
    // The filter is waiting for connections on URL suffixed with filterSuffix
    // and presents SP metadata there
    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    
    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }
    
    // Filter automatically generates default SP metadata
    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
//        metadataGenerator.setEntityId("com:vdenotaris:spring:sp");
        metadataGenerator.setExtendedMetadata(extendedMetadata());
//        metadataGenerator.setIncludeDiscoveryExtension(false);
//        metadataGenerator.setKeyManager(keyManager()); 
        return metadataGenerator;
    }

}

//migration notes:

//         logoutHandler.setInvalidateHttpSession(true); as false