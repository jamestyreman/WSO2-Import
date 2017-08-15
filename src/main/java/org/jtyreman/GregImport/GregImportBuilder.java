package org.jtyreman.GregImport;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.BuildListener;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Recorder;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;

import java.io.IOException;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.ws.rs.core.MediaType;

import org.apache.commons.io.FilenameUtils;
import org.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import com.sun.jersey.core.util.Base64;
import com.sun.jersey.multipart.FormDataMultiPart;
import com.sun.jersey.multipart.MultiPart;
import com.sun.jersey.multipart.file.FileDataBodyPart;
import com.sun.jersey.multipart.impl.MultiPartWriter;
import com.sun.jersey.client.urlconnection.HTTPSProperties;

/**
 * Sample {@link Recorder}.
 *
 * <p>
 * When the user configures the project and enables this builder,
 * {@link DescriptorImpl#newInstance(StaplerRequest)} is invoked and a new
 * {@link GregImportBuilder} is created. The created instance is persisted to
 * the project configuration XML by using XStream, so this allows you to use
 * instance fields (like {@link #artefactName}) to remember the configuration.
 *
 * <p>
 * When a build is performed, the {@link #perform} method will be invoked.
 *
 * @author James Tyreman
 */
public class GregImportBuilder extends Recorder{

	private final String artefactName;
	private final String artefactVersion;
	private final boolean restService;
	private final boolean soapService;
	private final String artefactNamespace;
	private final String artefactContext;
	private final String artefactDescription;
	private final boolean processWsdls;
	private final boolean processXsds;
	
	// Fields in config.jelly must match the parameter names in the
	// "DataBoundConstructor"
	@DataBoundConstructor
	public GregImportBuilder(String artefactName, String artefactVersion, boolean restService,
			boolean soapService, String artefactNamespace, String artefactContext, String artefactDescription, boolean processWsdls, boolean processXsds) {
		this.artefactName = artefactName;
		this.artefactVersion = artefactVersion;
		this.restService = restService;
		this.soapService = soapService;
		this.artefactNamespace = artefactNamespace;
		this.artefactContext = artefactContext;
		this.artefactDescription = artefactDescription;
		this.processWsdls = processWsdls;
		this.processXsds = processXsds;
	}

	/**
	 * We'll use this from the {@code config.jelly}.
	 */

	public String getArtefactName() {
		return artefactName;
	}

	public String getArtefactVersion() {
		return artefactVersion;
	}

	public boolean getRestService() {
		return restService;
	}

	public boolean getSoapService() {
		return soapService;
	}
	
	public String getArtefactNamespace() {
		return artefactNamespace;
	}
	
	public String getArtefactContext() {
		return artefactContext;
	}
	
	public String getArtefactDescription() {
		return artefactDescription;
	}
	
	public boolean getProcessWsdls() {
		return processWsdls;
	}
	
	public boolean getProcessXsds() {
		return processXsds;
	}
	
	@Override
	public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener) {
		
		listener.getLogger().println("Started Sending Details to GREG" );
		final String url = getDescriptor().getGregUrl();
		final String user = getDescriptor().getGregUser();
		final Secret password = getDescriptor().getGregPassword();
			
		
		WebResource service = getService(url, user, password);

		//Publish Resources / Services
		
		listener.getLogger().println("POST: adding Service to WSO2 " );
		if (getRestService()) {
			String json = "{ \"name\" : \"" + getArtefactName() + "\", \"type\":\"restservice\",\"version\":\""
					+ getArtefactVersion() + "\", \"context\" : \""+getArtefactContext() + "\", \"description\" : \"" + getArtefactDescription() + "\" }";
			listener.getLogger().println("POST: adding REST Service to WSO2 " + json);
			service.path("governance").path("restservices").accept(MediaType.APPLICATION_JSON).type(MediaType.APPLICATION_JSON).post(json);
		} 
		
		if (getSoapService()) {
			String json = "{ \"name\" : \"" + getArtefactName() + "\", \"type\":\"soapservice\",\"version\":\""
					+ getArtefactVersion() + "\", \"namespace\" : \""+getArtefactNamespace()  + "\", \"description\" : \"" + getArtefactDescription() + "\" }";
			listener.getLogger().println("POST: adding SOAP Service to WSO2 " + json);
			service.path("governance").path("soapservices").accept(MediaType.APPLICATION_JSON).type(MediaType.APPLICATION_JSON).post(json);
		}
		
		
		//Publish Assets
		
		//Connect to API
		ClientResponse response = service.path("publisher").path("apis").path("authenticate").queryParam("username", "admin").queryParam("password", "admin").accept(MediaType.APPLICATION_JSON).type(MediaType.APPLICATION_FORM_URLENCODED).post(ClientResponse.class);
		String output = response.getEntity(String.class);
		JSONObject jsonObj = new JSONObject(output);
		
		//Store Session ID
		
		String sessionId = jsonObj.getJSONObject("data").getString("sessionId");
		listener.getLogger().println("SessionID is " + sessionId);
		

		String workspacePath = build.getProject().getWorkspace().toString(); 
		String jobBaseUrl = build.getProject().getAbsoluteUrl();
		String jobName = build.getProject().getDisplayName();
		ArrayList<File> allFiles = new ArrayList<File>();
		listf(workspacePath, allFiles, listener);
		
		if(getProcessXsds()){
			//Process Schemas		
			for(File file : allFiles){
				String fileExt = FilenameUtils.getExtension(file.getName());
	        	if (fileExt != null && (fileExt.equals("xsd") || fileExt.equals("XSD"))){
	        		 listener.getLogger().println("Schema " + file.getName() + " will be processed.");
	        		 String path = file.getPath();
	        		 String wsLocation = path.substring(path.indexOf(jobName) + jobName.length());
	        		 wsLocation = wsLocation.replace("\\", "/");
	        		 FormDataMultiPart formData = new FormDataMultiPart() ;              
	                 formData.field("overview_name",file.getName()); 
	                 formData.field("overview_version", "1.0.0"); 
	                 formData.field("overview_url", jobBaseUrl + "ws" + wsLocation); 
	                 formData.field("addNewAssetButton", "Create");
	                 ClientResponse xsdResponse = service.path("publisher").path("apis").path("assets").queryParam("type", "schema").accept(MediaType.APPLICATION_JSON).type(MediaType.MULTIPART_FORM_DATA).header("Cookie","JSESSIONID="+sessionId).post(ClientResponse.class, formData);
	        	}
			}
		}
		
		if(getProcessWsdls()){
		//Process WSDL's
			for(File file : allFiles){
			String fileExt = FilenameUtils.getExtension(file.getName());
	        	if (fileExt != null && (fileExt.equals("wsdl") || fileExt.equals("WSDL"))){
	        		listener.getLogger().println("WSDL " + file.getName() + " will be processed.");
	        		 String path = file.getPath();
	        		 String wsLocation = path.substring(path.indexOf(jobName) + jobName.length());
	        		 wsLocation = wsLocation.replace("\\", "/");
	        		 FormDataMultiPart formData = new FormDataMultiPart() ;              
	                 formData.field("overview_name",file.getName()); 
	                 formData.field("overview_version", "1.0.0"); 
	                 formData.field("overview_url", jobBaseUrl + "ws" + wsLocation); 
	                 formData.field("addNewAssetButton", "Create");
	                 ClientResponse xsdResponse = service.path("publisher").path("apis").path("assets").queryParam("type", "wsdl").accept(MediaType.APPLICATION_JSON).type(MediaType.MULTIPART_FORM_DATA).header("Cookie","JSESSIONID="+sessionId).post(ClientResponse.class, formData);
	        	}
			}	
		}
		
		listener.getLogger().println("Finished Sending Details to GREG" );
		return true;
		
	
	
	}
	
	public void listf(String directoryName, ArrayList<File> files, BuildListener listener) {
	    File directory = new File(directoryName);

	    // get all the files from a directory
	    File[] fList = directory.listFiles();
	    if(fList != null){
	    for (File file : fList) {
	        if (file.isFile()) {
	        	files.add(file);  	
	        } else if (file.isDirectory()) {
	            listf(file.getAbsolutePath(), files, listener);
	        }
	    }
	    }
	}
	
	
    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.NONE;
    }
    

	private static WebResource getService(final String url, final String user, final Secret password) {
        
		Client client = Client.create(configureClient());
        client.addFilter(new HTTPBasicAuthFilter(user, Secret.toString(password)));
		WebResource service = client.resource(url);
		return service;
	}
	

	public static ClientConfig configureClient() {
		TrustManager[ ] certs = new TrustManager[ ] {
	            new X509TrustManager() {
					@Override
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}
					@Override
					public void checkServerTrusted(X509Certificate[] chain, String authType)
							throws CertificateException {
					}
					@Override
					public void checkClientTrusted(X509Certificate[] chain, String authType)
							throws CertificateException {
					}
				}
	    };
	    SSLContext ctx = null;
	    try {
	        ctx = SSLContext.getInstance("TLS");
	        ctx.init(null, certs, new SecureRandom());
	    } catch (java.security.GeneralSecurityException ex) {
	    	
	    }
	    if(ctx != null){
	    HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
	    }
	    
	    ClientConfig config = new DefaultClientConfig();
	    config.getClasses().add(MultiPartWriter.class);
	    try {
		    config.getProperties().put(HTTPSProperties.PROPERTY_HTTPS_PROPERTIES, new HTTPSProperties(
		        new HostnameVerifier() {
					@Override
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
		        }, 
		        ctx
		    ));
	    } catch(Exception e) {
	    }
	    return config;
	}
	
	@Override
	public DescriptorImpl getDescriptor() {
		return (DescriptorImpl) super.getDescriptor();
	}

	/**
	 * Descriptor for {@link GregImportBuilder}. Used as a singleton. The class
	 * is marked as public so that it can be accessed from views.
	 *
	 * <p>
	 * See
	 * {@code src/main/resources/org/jtyreman/GregImport/GregImportBuilder/*.jelly}
	 * for the actual HTML fragment for the configuration screen.
	 */
	@Extension // This indicates to Jenkins that this is an implementation of an
				// extension point.
	public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {
		/**
		 * To persist global configuration information, simply store it in a
		 * field and call save().
		 *
		 * <p>
		 * If you don't want fields to be persisted, use {@code transient}.
		 */
		private String gregUrl;
		private String gregUser;
		private Secret gregPassword;


		/**
		 * Performs on-the-fly validation of the form field 'name'.
		 *
		 * @param value
		 *            This parameter receives the value that the user has typed.
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 *         <p>
		 *         Note that returning {@link FormValidation#error(String)} does
		 *         not prevent the form from being saved. It just means that a
		 *         message will be displayed to the user.
		 */
		
		public FormValidation doCheckKey(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error("Please set a key");
            if (value.length() < 4)
                return FormValidation.warning("Isn't the key too short?");
            return FormValidation.ok();
        }
        public FormValidation doCheckValue(@QueryParameter String value)
                throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error("Please set a value");
            if (value.length() < 4)
                return FormValidation.warning("Isn't the key too short?");
            return FormValidation.ok();
        }
        
		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			// Indicates that this builder can be used with all kinds of project
			// types
			return true;
		}

		/**
		 * This human readable name is used in the configuration screen.
		 */
		   public String getDisplayName() {
	            return "Add artefact to WSO2 Registry";
	        }


		@Override
		public boolean configure(StaplerRequest req, net.sf.json.JSONObject formData) throws FormException {
			// To persist global configuration information,
			// set that to properties and call save().
			gregUrl = formData.getString("gregUrl");
			gregUser = formData.getString("gregUser");
			gregPassword = Secret.fromString( formData.getString("gregPassword") );
			// ^Can also use req.bindJSON(this, formData);
			// (easier when there are many fields; need set* methods for this,
			// like setUseFrench)
			save();
			return super.configure(req, formData);
		}

		public String getGregUrl() {
			return gregUrl;
		}

		public String getGregUser() {
			return gregUser;
		}

		public Secret getGregPassword() {
			return gregPassword;
		}

	}
}
