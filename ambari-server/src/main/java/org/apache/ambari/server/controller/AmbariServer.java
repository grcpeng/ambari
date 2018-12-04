/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ambari.server.controller;

import com.google.common.base.Joiner;
import com.google.common.util.concurrent.ServiceManager;
import com.google.gson.Gson;
import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Scopes;
import com.google.inject.Singleton;
import com.google.inject.name.Named;
import com.google.inject.persist.Transactional;
import com.sun.jersey.spi.container.servlet.ServletContainer;
import java.io.File;
import java.io.IOException;
import java.net.Authenticator;
import java.net.BindException;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.Map;
import java.util.logging.LogManager;
import javax.crypto.BadPaddingException;
import javax.servlet.DispatcherType;
import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.StateRecoveryManager;
import org.apache.ambari.server.StaticallyInject;
import org.apache.ambari.server.actionmanager.ActionManager;
import org.apache.ambari.server.actionmanager.HostRoleCommandFactory;
import org.apache.ambari.server.agent.HeartBeatHandler;
import org.apache.ambari.server.agent.rest.AgentResource;
import org.apache.ambari.server.api.AmbariErrorHandler;
import org.apache.ambari.server.api.AmbariPersistFilter;
import org.apache.ambari.server.api.MethodOverrideFilter;
import org.apache.ambari.server.api.UserNameOverrideFilter;
import org.apache.ambari.server.api.rest.BootStrapResource;
import org.apache.ambari.server.api.services.AmbariMetaInfo;
import org.apache.ambari.server.api.services.BaseService;
import org.apache.ambari.server.api.services.KeyService;
import org.apache.ambari.server.api.services.PersistKeyValueImpl;
import org.apache.ambari.server.api.services.PersistKeyValueService;
import org.apache.ambari.server.api.services.stackadvisor.StackAdvisorBlueprintProcessor;
import org.apache.ambari.server.api.services.stackadvisor.StackAdvisorHelper;
import org.apache.ambari.server.audit.AuditLoggerModule;
import org.apache.ambari.server.audit.request.RequestAuditLogger;
import org.apache.ambari.server.bootstrap.BootStrapImpl;
import org.apache.ambari.server.checks.DatabaseConsistencyCheckHelper;
import org.apache.ambari.server.checks.DatabaseConsistencyCheckResult;
import org.apache.ambari.server.configuration.ComponentSSLConfiguration;
import org.apache.ambari.server.configuration.Configuration;
import org.apache.ambari.server.configuration.SingleFileWatch;
import org.apache.ambari.server.configuration.spring.AgentStompConfig;
import org.apache.ambari.server.configuration.spring.ApiSecurityConfig;
import org.apache.ambari.server.configuration.spring.ApiStompConfig;
import org.apache.ambari.server.controller.internal.AbstractControllerResourceProvider;
import org.apache.ambari.server.controller.internal.AmbariPrivilegeResourceProvider;
import org.apache.ambari.server.controller.internal.BaseClusterRequest;
import org.apache.ambari.server.controller.internal.BlueprintResourceProvider;
import org.apache.ambari.server.controller.internal.ClusterPrivilegeResourceProvider;
import org.apache.ambari.server.controller.internal.ClusterResourceProvider;
import org.apache.ambari.server.controller.internal.HostResourceProvider;
import org.apache.ambari.server.controller.internal.PermissionResourceProvider;
import org.apache.ambari.server.controller.internal.PrivilegeResourceProvider;
import org.apache.ambari.server.controller.internal.StackAdvisorResourceProvider;
import org.apache.ambari.server.controller.internal.StackDefinedPropertyProvider;
import org.apache.ambari.server.controller.internal.StackDependencyResourceProvider;
import org.apache.ambari.server.controller.internal.UserPrivilegeResourceProvider;
import org.apache.ambari.server.controller.internal.ViewPermissionResourceProvider;
import org.apache.ambari.server.controller.metrics.ThreadPoolEnabledPropertyProvider;
import org.apache.ambari.server.controller.utilities.KerberosChecker;
import org.apache.ambari.server.controller.utilities.KerberosIdentityCleaner;
import org.apache.ambari.server.events.AmbariPropertiesChangedEvent;
import org.apache.ambari.server.events.publishers.AmbariEventPublisher;
import org.apache.ambari.server.ldap.LdapModule;
import org.apache.ambari.server.metrics.system.MetricsService;
import org.apache.ambari.server.orm.GuiceJpaInitializer;
import org.apache.ambari.server.orm.PersistenceType;
import org.apache.ambari.server.orm.dao.BlueprintDAO;
import org.apache.ambari.server.orm.dao.ClusterDAO;
import org.apache.ambari.server.orm.dao.GroupDAO;
import org.apache.ambari.server.orm.dao.MetainfoDAO;
import org.apache.ambari.server.orm.dao.PermissionDAO;
import org.apache.ambari.server.orm.dao.PrincipalDAO;
import org.apache.ambari.server.orm.dao.PrivilegeDAO;
import org.apache.ambari.server.orm.dao.ResourceDAO;
import org.apache.ambari.server.orm.dao.TopologyRequestDAO;
import org.apache.ambari.server.orm.dao.UserDAO;
import org.apache.ambari.server.orm.dao.ViewInstanceDAO;
import org.apache.ambari.server.orm.entities.MetainfoEntity;
import org.apache.ambari.server.orm.entities.UserEntity;
import org.apache.ambari.server.resources.ResourceManager;
import org.apache.ambari.server.resources.api.rest.GetResource;
import org.apache.ambari.server.scheduler.ExecutionScheduleManager;
import org.apache.ambari.server.security.AmbariServerSecurityHeaderFilter;
import org.apache.ambari.server.security.AmbariViewsSecurityHeaderFilter;
import org.apache.ambari.server.security.CertificateManager;
import org.apache.ambari.server.security.SecurityFilter;
import org.apache.ambari.server.security.authorization.Users;
import org.apache.ambari.server.security.unsecured.rest.CertificateDownload;
import org.apache.ambari.server.security.unsecured.rest.CertificateSign;
import org.apache.ambari.server.security.unsecured.rest.ConnectionInfo;
import org.apache.ambari.server.serveraction.kerberos.stageutils.KerberosKeytabController;
import org.apache.ambari.server.stack.UpdateActiveRepoVersionOnStartup;
import org.apache.ambari.server.state.Clusters;
import org.apache.ambari.server.topology.AmbariContext;
import org.apache.ambari.server.topology.BlueprintFactory;
import org.apache.ambari.server.topology.SecurityConfigurationFactory;
import org.apache.ambari.server.topology.TopologyManager;
import org.apache.ambari.server.topology.TopologyRequestFactoryImpl;
import org.apache.ambari.server.utils.AmbariPath;
import org.apache.ambari.server.utils.RetryHelper;
import org.apache.ambari.server.utils.StageUtils;
import org.apache.ambari.server.utils.VersionUtils;
import org.apache.ambari.server.view.AmbariViewsMDCLoggingFilter;
import org.apache.ambari.server.view.ViewDirectoryWatcher;
import org.apache.ambari.server.view.ViewRegistry;
import org.apache.ambari.server.view.ViewThrottleFilter;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpVersion;
import org.apache.log4j.PropertyConfigurator;
import org.apache.velocity.app.Velocity;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SessionIdManager;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.server.session.DefaultSessionIdManager;
import org.eclipse.jetty.server.session.SessionHandler;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.servlets.GzipFilter;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.request.RequestContextListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.DispatcherServlet;

@Singleton
public class AmbariServer {
	public static final String VIEWS_URL_PATTERN = "/api/v1/views/*";
	/**
	 * Dispatcher types for webAppContext.addFilter.
	 */
	public static final EnumSet<DispatcherType> DISPATCHER_TYPES = EnumSet.of(DispatcherType.REQUEST);
	// Set velocity logger
	protected static final String VELOCITY_LOG_CATEGORY = "VelocityLogger";
	private static final Logger LOG = LoggerFactory.getLogger(AmbariServer.class);
	/**
	 * The thread name prefix for threads handling agent requests.
	 */
	private static final String AGENT_THREAD_POOL_NAME = "qtp-ambari-agent";
	/**
	 * The thread name prefix for threads handling REST API requests.
	 */
	private static final String CLIENT_THREAD_POOL_NAME = "ambari-client-thread";
	private static final int DEFAULT_ACCEPTORS_COUNT = 1;
	private static final String CLASSPATH_CHECK_CLASS = "org/apache/ambari/server/controller/AmbariServer.class";
	private static final String CLASSPATH_SANITY_CHECK_FAILURE_MESSAGE = "%s class is found in multiple jar files. Possible reasons include multiple ambari server jar files in the ambari classpath.\n" +
		String.format("Check for additional ambari server jar files and check that %s matches only one file.", AmbariPath.getPath("/usr/lib/ambari-server/ambari-server*.jar"));
	private static AmbariManagementController clusterController = null;

	static {
		Velocity.setProperty("runtime.log.logsystem.log4j.logger", VELOCITY_LOG_CATEGORY);
	}

	static {
		Enumeration<URL> ambariServerClassUrls;
		try {
			ambariServerClassUrls = AmbariServer.class.getClassLoader().getResources(CLASSPATH_CHECK_CLASS);

			int ambariServerClassUrlsSize = 0;
			while (ambariServerClassUrls.hasMoreElements()) {
				ambariServerClassUrlsSize++;
				URL url = ambariServerClassUrls.nextElement();
				LOG.info(String.format("Found %s class in %s", CLASSPATH_CHECK_CLASS, url.getPath()));
			}
			if (ambariServerClassUrlsSize > 1) {
				throw new RuntimeException(String.format(CLASSPATH_SANITY_CHECK_FAILURE_MESSAGE, CLASSPATH_CHECK_CLASS));
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	final String CONTEXT_PATH = "/";
	final String DISABLED_ENTRIES_SPLITTER = "\\|";
	public volatile boolean running = true; // true while controller runs
	@Inject
	Configuration configs;

	@Inject
	CertificateManager certMan;

	@Inject
	Injector injector;

	@Inject
	AmbariMetaInfo ambariMetaInfo;

	@Inject
	MetainfoDAO metainfoDAO;

	@Inject
	@Named("dbInitNeeded")
	boolean dbInitNeeded;
	/**
	 * The singleton view registry.
	 */
	@Inject
	ViewRegistry viewRegistry;
	/**
	 * The handler list for deployed web apps.
	 */
	@Inject
	AmbariHandlerList handlerList;
	/**
	 * Session manager.
	 */
	@Inject
	SessionHandler sessionHandler;
	@Inject
	DelegatingFilterProxy springSecurityFilter;
	@Inject
	ViewDirectoryWatcher viewDirectoryWatcher;
	@Inject
	SessionHandlerConfigurer sessionHandlerConfigurer;
	private Server server = null;
	/**
	 * Guava service manager singleton (bound with {@link Scopes#SINGLETON}).
	 */
	@Inject
	private ServiceManager serviceManager;

	public static AmbariManagementController getController() {
		return clusterController;
	}

	public static void setController(AmbariManagementController controller) {
		clusterController = controller;
	}

	public static void main(String[] args) throws Exception {
		//启动日志
		logStartup();
		//注入依赖
		Injector injector = Guice.createInjector(new ControllerModule(), new AuditLoggerModule(), new LdapModule());

		AmbariServer server = null;
		try {
			LOG.info("Getting the controller");

			// check if this instance is the active instance
			Configuration config = injector.getInstance(Configuration.class);
			if (!config.isActiveInstance()) {
				String errMsg = "This instance of ambari server is not designated as active. Cannot start ambari server." +
					"The property active.instance is set to false in ambari.properties";
				throw new AmbariException(errMsg);
			}

			setupProxyAuth();

			// Start and Initialize JPA
			GuiceJpaInitializer jpaInitializer = injector.getInstance(GuiceJpaInitializer.class);
			jpaInitializer.setInitialized(); // This must be called to alert Ambari that JPA is initialized.

			DatabaseConsistencyCheckHelper.checkDBVersionCompatible();

			server = injector.getInstance(AmbariServer.class);
			injector.getInstance(UpdateActiveRepoVersionOnStartup.class).process();
			// 管理server和agent证书
			CertificateManager certMan = injector.getInstance(CertificateManager.class);
			// 生成证书
			certMan.initRootCert();
			// 使用Kerberos principal和keytab检查Ambari server，以允许视图通过SPNEGO对集群组件进行身份验证。
			KerberosChecker.checkJaasConfiguration();
			// 注册视图实例
			ViewRegistry.initInstance(server.viewRegistry);
			// 配置用于Ambari和第三方服务之间的SSL通信。目前，SSL通信支持以下服务:Ambari metrics
			ComponentSSLConfiguration.instance().init(server.configs);
			server.run();
		} catch (Throwable t) {
			// Writing to system console is needed because loggers may not get flushed on exit and diagnostic information
			// may get lost.
			System.err.println("An unexpected error occured during starting Ambari Server.");
			t.printStackTrace();
			LOG.error("Failed to run the Ambari Server", t);
			if (server != null) {
				server.stop();
			}
			System.exit(-1);
		}
	}

	/**
	 * Logs startup properties.
	 */
	private static void logStartup() {
		final String linePrefix = "STARTUP_MESSAGE: ";

		final String classpathPropertyName = "java.class.path";
		final String classpath = System.getProperty(classpathPropertyName);

		String[] rawMessages = {
			linePrefix + "Starting AmbariServer.java executable",
			classpathPropertyName + " = " + classpath
		};
		//guava使用特定分隔符将字符串连接起来
		LOG.info(Joiner.on("\n" + linePrefix).join(rawMessages));
	}

	/**
	 * Sets up proxy authentication.  This must be done before the server is
	 * initialized since <code>AmbariMetaInfo</code> requires potential URL
	 * lookups that may need the proxy.
	 */
	public static void setupProxyAuth() {
		final String proxyUser = System.getProperty("http.proxyUser");
		final String proxyPass = System.getProperty("http.proxyPassword");

		// to skip some hosts from proxy, pipe-separate names using, i.e.:
		// -Dhttp.nonProxyHosts=*.domain.com|host.internal.net

		if (null != proxyUser && null != proxyPass) {
			LOG.info("Proxy authentication enabled");

			Authenticator.setDefault(new Authenticator() {
				@Override
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(proxyUser, proxyPass.toCharArray());
				}
			});
		} else {
			LOG.debug("Proxy authentication not specified");
		}
	}

	@SuppressWarnings("deprecation")
	public void run() throws Exception {
		// 安装桥处理程序，它将日志条目从jul重定向到Slf4J
		setupJulLogging();

		//Deprecated 静态注入替换等待持久服务启动
		performStaticInjection();
		// 如果使用内存中的数据库，则创建默认用户,如果使用自己配置的数据库，则跳过
		initDB();

		/**
		 * 客户端Jetty线程池 - 如果有需要可以扩大线程池!
		 * Client Jetty thread pool - widen the thread pool if needed !
		 */
		Integer clientAcceptors = configs.getClientApiAcceptors() != null ? configs
			.getClientApiAcceptors() : DEFAULT_ACCEPTORS_COUNT;
		/**
		 *   Jetty线程池由三种基本类型的线程组成:
		 *   Acceptors
		 *   Selectors
		 *   Threads which can actually do stuff
		 *   selectChannelConnector使用runtime.availableprocessor()作为确定要创建多少个acceptors and selectors。
		 *   如果处理器的数量太大，那么就没有线程来满足连接请求。该方法确保正确配置池大小，并考虑到可用处理器的数量(socket x core x thread-per-core)。
		 *   如果配置的池大小太小，那么这将记录一个警告并增加池大小，以确保至少有20个可用线程用于请求。
		 */
		server = configureJettyThreadPool(clientAcceptors, CLIENT_THREAD_POOL_NAME,
			configs.getClientThreadPoolSize());

		// 管理跨多个上下文的会话id。
		final SessionIdManager sessionIdManager = new DefaultSessionIdManager(server);
		sessionHandler.setSessionIdManager(sessionIdManager);
		server.setSessionIdManager(sessionIdManager);
		/**
		 *  Agent Jetty线程池 - 如果有需要可以扩大线程池!
		 * Agent Jetty thread pool - widen the thread pool if needed !
		 */
		Integer agentAcceptors = configs.getAgentApiAcceptors() != null ?
			configs.getAgentApiAcceptors() : DEFAULT_ACCEPTORS_COUNT;

		Server serverForAgent = configureJettyThreadPool(agentAcceptors * 2,
			AGENT_THREAD_POOL_NAME, configs.getAgentThreadPoolSize());

		//根据Ambari配置修改系统变量
		setSystemProperties(configs);
		//如果没有添加跳过选项，此方法将执行数据库一致性检查
		runDatabaseConsistencyCheck();

		try {
			/**
			 * 独立的XML应用程序上下文，从类路径中获取上下文定义文件，将普通路径解释为包含包路径的类路径资源名(例如“mypackage/myresource.txt”)。
			 * 适用于测试工具以及嵌入在jar中的应用程序上下文。
			 * 配置位置默认值可以通过AbstractRefreshableConfigApplicationContext.getConfigLocations()重写，
			 * 配置位置可以表示具体的文件，比如“/myfiles/context.xml“或ant样式的模式，如”/myfiles/*-context。(有关模式细节，请参阅AntPathMatcher javadoc)。
			 * 注意:对于多个配置位置，以后的bean定义将覆盖以前加载的文件中定义的。这可以通过额外的XML文件故意覆盖特定bean定义。
			 * 这是一个简单的、一站式的应用程序上下文。考虑结合使用GenericApplicationContext类和XmlBeanDefinitionReader来实现更灵活的上下文设置。
			 */
			ClassPathXmlApplicationContext parentSpringAppContext =
				new ClassPathXmlApplicationContext();
			/**
			 * 从接口复制的描述:ConfigurableApplicationContext
			 * 加载或刷新配置的持久表示，可能是XML文件、属性文件或关系数据库模式。
			 * 由于这是一种启动方法，如果失败，应该销毁已经创建的单例，以避免悬空资源。换句话说，在调用该方法之后，要么全部实例化，要么完全不实例化。
			 */
			parentSpringAppContext.refresh();
			ConfigurableListableBeanFactory factory = parentSpringAppContext.getBeanFactory();

			/**
			 * 在bean注册中心中，以给定的bean名称将给定的现有对象注册为单例对象。假定给定的实例被完全初始化;
			 * 注册中心不会执行任何初始化回调(特别是，它不会调用InitializingBean的afterPropertiesSet方法)。
			 * 配置位置默认值可以通过AbstractRefreshableConfigApplicationContext.getConfigLocations()重写，配置位置可以表示具体的文件，
			 * 比如“/myfiles/给定的实例也不会接收任何销毁回调(比如DisposableBean的销毁方法)。
			 * 在完整的bean工厂中运行时:如果您的bean应该接收初始化和/或销毁回调，则注册bean定义而不是现有实例。
			 * 通常在注册中心配置期间调用，但也可用于单例运行时注册。因此，注册中心实现应该同步单例访问;如果它支持BeanFactory的单例延迟初始化，那么无论如何它都必须这样做。
			 */
			factory.registerSingleton("injector", injector);
			//todo unable to register Users class as Spring @Bean since it tries to process @Inject annotations, investigate
			factory.registerSingleton("ambariUsers", injector.getInstance(Users.class));

			//create spring context for web api
			/**
			 * WebApplicationContext实现，它接受带注释的类作为输入—特别是@Configuration-annotated类，但是也接受普通的@Component类和使用javax.inject注解的兼容的JSR-330类。
			 * 允许逐个注册类(指定类名作为配置位置)以及类路径扫描(指定基本包作为配置位置)。这本质上相当于一个web环境的AnnotationConfigApplicationContext。
			 * 要使用这个应用程序上下文，必须将contextClass的context-param设置为这个类的完全限定名。从Spring3.1开始，当使用新的基于web.xml的WebApplicationInitializer代码的替代方案时，
			 * 这个类也可以直接实例化并注入到Spring的DispatcherServlet或ContextLoaderListener中。有关详细信息和用法示例，请参阅其Javadoc。与XmlWebApplicationContext不同，没有假定默认的配置类位置。
			 * 相反，需要为ContextLoader和/或为FrameworkServlet设置“contextConfigLocation”init-param。参数值可能包含完全限定的类名和用于扫描组件的基本包。
			 * 有关如何处理这些位置的详细信息，请参阅loadBeanDefinitions(org.springframework.beans.factory.support.DefaultListableBeanFactory)。
			 * 作为设置“contextConfigLocation”参数的替代方法，用户可以实现一个applicationcontextinitiextinitializer化子，并设置“contextInitializerClasses”上下文-param/init-param。在这种情况下，
			 * 用户应该更喜欢AbstractApplicationContext.refresh()和scan(String…)方法，而不是AbstractRefreshableConfigApplicationContext.setConfigLocation(String)方法，后者主要用于ContextLoader。
			 * 注意:对于多个@Configuration类，以后的@Bean定义将覆盖以前加载的文件中定义的类。这可以通过一个额外的配置类故意覆盖特定bean定义。
			 */
			AnnotationConfigWebApplicationContext apiContext = new AnnotationConfigWebApplicationContext();
			/**
			 * 设置此应用程序上下文的父上下文。
			 * 如果父环境是非空的，且其环境是ConfigurableEnvironment实例，则父环境将与这个(子)应用程序上下文环境合并。
			 */
			apiContext.setParent(parentSpringAppContext);
			/**
			 * 注册一个或多个要处理的带注释的类。
			 * 注意，为了上下文完整地处理新类，必须调用AbstractApplicationContext.refresh()。
			 */
			apiContext.register(ApiSecurityConfig.class);
			//refresh will be called in ContextLoaderListener
			AnnotationConfigWebApplicationContext apiDispatcherContext = new AnnotationConfigWebApplicationContext();
			apiDispatcherContext.register(ApiStompConfig.class);
			DispatcherServlet apiDispatcherServlet = new DispatcherServlet(apiDispatcherContext);

			AnnotationConfigWebApplicationContext agentDispatcherContext = new AnnotationConfigWebApplicationContext();
			agentDispatcherContext.register(AgentStompConfig.class);
			DispatcherServlet agentDispatcherServlet = new DispatcherServlet(agentDispatcherContext);
			/**
			 * 对context handler的扩展允许使用ServletHandler以及可选的会话和安全处理程序等简单构造上下文。
			 * 新的ServletContext(“/context”,Context.SESSIONS | Context.NO_SECURITY);
			 * 这个类应该称为ServletContext，但是这会导致与ServletContext混淆。
			 */
			ServletContextHandler root = new ServletContextHandler(
				ServletContextHandler.SECURITY | ServletContextHandler.SESSIONS);

			/**
			 * 使用静态值和配置文件中的值执行root handler的基本配置。
			 */
			configureRootHandler(root);
			sessionHandlerConfigurer.configureSessionHandler(sessionHandler);
			root.setSessionHandler(sessionHandler);

			//ContextLoaderListener handles all work on registration in servlet container'
			/**
			 * 添加EventListener(事件监听器)将一个事件监听器添加到列表中。@see org.eclipse.jetty.server.handler.ContextHandler # addEventListener()。还添加与SessionHandler相关的会话侦听器。
			 */
			root.addEventListener(new ContextLoaderListener(apiContext));

			certMan.initRootCert();

			// the agent communication (heartbeats, registration, etc) is stateless and does not use sessions.
			/**
			 * 代理通信(心跳、注册等)是无状态的，不使用会话。
			 */
			ServletContextHandler agentroot = new ServletContextHandler(
				serverForAgent, "/", ServletContextHandler.NO_SESSIONS);

			AnnotationConfigWebApplicationContext agentApiContext = new AnnotationConfigWebApplicationContext();
			agentApiContext.setParent(parentSpringAppContext);

			if (configs.isAgentApiGzipped()) {
				configureHandlerCompression(agentroot);
			}
			agentroot.addEventListener(new ContextLoaderListener(agentApiContext));

			ServletHolder rootServlet = root.addServlet(DefaultServlet.class, "/");
			rootServlet.setInitParameter("dirAllowed", "false");
			rootServlet.setInitParameter("precompressed", "gzip=.gz");
			rootServlet.setInitOrder(1);

			/* Configure default servlet for agent server */
			rootServlet = agentroot.addServlet(DefaultServlet.class, "/");
			rootServlet.setInitOrder(1);

			// Conditionally adds security-related headers to all HTTP responses.
			root.addFilter(new FilterHolder(injector.getInstance(AmbariServerSecurityHeaderFilter.class)), "/*", DISPATCHER_TYPES);

			// The security header filter - conditionally adds security-related headers to the HTTP response for Ambari Views
			// requests.
			root.addFilter(new FilterHolder(injector.getInstance(AmbariViewsSecurityHeaderFilter.class)), VIEWS_URL_PATTERN,
				DISPATCHER_TYPES);

			// since views share the REST API threadpool, a misbehaving view could
			// consume all of the available threads and effectively cause a loss of
			// service for Ambari
			root.addFilter(new FilterHolder(injector.getInstance(ViewThrottleFilter.class)),
				VIEWS_URL_PATTERN, DISPATCHER_TYPES);

			// adds MDC info for views logging
			root.addFilter(new FilterHolder(injector.getInstance(AmbariViewsMDCLoggingFilter.class)),
				VIEWS_URL_PATTERN, DISPATCHER_TYPES);

			// session-per-request strategy for api
			root.addFilter(new FilterHolder(injector.getInstance(AmbariPersistFilter.class)), "/api/*", DISPATCHER_TYPES);
			root.addFilter(new FilterHolder(new MethodOverrideFilter()), "/api/*", DISPATCHER_TYPES);

			// register listener to capture request context
			root.addEventListener(new RequestContextListener());
			root.addFilter(new FilterHolder(springSecurityFilter), "/api/*", DISPATCHER_TYPES);
			root.addFilter(new FilterHolder(new UserNameOverrideFilter()), "/api/v1/users/*", DISPATCHER_TYPES);

			// session-per-request strategy for agents
			agentroot.addFilter(new FilterHolder(injector.getInstance(AmbariPersistFilter.class)), "/agent/*", DISPATCHER_TYPES);
			agentroot.addFilter(SecurityFilter.class, "/*", DISPATCHER_TYPES);

			Map<String, String> configsMap = configs.getConfigsMap();

			// Agents download cert on on-way connector but always communicate on
			// two-way connector for server-agent communication
			ServerConnector agentOneWayConnector = createSelectChannelConnectorForAgent(serverForAgent, configs.getOneWayAuthPort(), false, agentAcceptors);
			ServerConnector agentTwoWayConnector = createSelectChannelConnectorForAgent(serverForAgent, configs.getTwoWayAuthPort(), configs.isTwoWaySsl(), agentAcceptors);

			serverForAgent.addConnector(agentOneWayConnector);
			serverForAgent.addConnector(agentTwoWayConnector);

			ServletHolder sh = new ServletHolder(ServletContainer.class);
			sh.setInitParameter("com.sun.jersey.config.property.resourceConfigClass",
				"com.sun.jersey.api.core.PackagesResourceConfig");

			sh.setInitParameter("com.sun.jersey.config.property.packages",
				"org.apache.ambari.server.api.rest;" +
					"org.apache.ambari.server.api.services;" +
					"org.apache.ambari.eventdb.webservice;" +
					"org.apache.ambari.server.api");

			sh.setInitParameter("com.sun.jersey.api.json.POJOMappingFeature", "true");
			root.addServlet(sh, "/api/v1/*");
			sh.setInitOrder(2);

			ServletHolder springDispatcherServlet = new ServletHolder("springDispatcherServlet", apiDispatcherServlet);
			springDispatcherServlet.setInitOrder(3);
			root.addServlet(springDispatcherServlet, "/api/stomp/*");

			ServletHolder agentSpringDispatcherServlet =
				new ServletHolder("agentSpringDispatcherServlet", agentDispatcherServlet);
			agentSpringDispatcherServlet.setInitOrder(2);
			agentroot.addServlet(agentSpringDispatcherServlet, "/agent/stomp/*");

			SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

			viewRegistry.readViewArchives();

			//Check and load requestlog handler.
			loadRequestlogHandler(handlerList, serverForAgent, configsMap);

			enableLog4jMonitor(configsMap);

			if (configs.isGzipHandlerEnabledForJetty()) {
				GzipHandler gzipHandler = new GzipHandler();
				gzipHandler.setHandler(root);
				//TODO minimal set, perhaps is needed to add some other mime types
				gzipHandler.setIncludedMimeTypes("text/html", "text/plain", "text/xml", "text/css", "application/javascript",
					"application/x-javascript", "application/xml", "application/x-www-form-urlencoded", "application/json");
				handlerList.addHandler(gzipHandler);
			} else {
				handlerList.addHandler(root);
			}

			server.setHandler(handlerList);

			ServletHolder agent = new ServletHolder(ServletContainer.class);
			agent.setInitParameter("com.sun.jersey.config.property.resourceConfigClass",
				"com.sun.jersey.api.core.PackagesResourceConfig");
			agent.setInitParameter("com.sun.jersey.config.property.packages",
				"org.apache.ambari.server.agent.rest;" + "org.apache.ambari.server.api");
			agent.setInitParameter("com.sun.jersey.api.json.POJOMappingFeature", "true");
			agentroot.addServlet(agent, "/agent/v1/*");
			agent.setInitOrder(3);

			AgentResource.startHeartBeatHandler();
			LOG.info("********** Started Heartbeat handler **********");

			ServletHolder cert = new ServletHolder(ServletContainer.class);
			cert.setInitParameter("com.sun.jersey.config.property.resourceConfigClass",
				"com.sun.jersey.api.core.PackagesResourceConfig");
			cert.setInitParameter("com.sun.jersey.config.property.packages",
				"org.apache.ambari.server.security.unsecured.rest;" + "org.apache.ambari.server.api");

			cert.setInitParameter("com.sun.jersey.api.json.POJOMappingFeature", "true");
			agentroot.addServlet(cert, "/*");
			cert.setInitOrder(4);

			File resourcesDirectory = new File(configs.getResourceDirPath());
			ServletHolder resources = new ServletHolder(DefaultServlet.class);
			resources.setInitParameter("resourceBase", resourcesDirectory.getParent());
			root.addServlet(resources, "/resources/*");
			resources.setInitOrder(5);

			if (configs.csrfProtectionEnabled()) {
				sh.setInitParameter("com.sun.jersey.spi.container.ContainerRequestFilters",
					"org.apache.ambari.server.api.AmbariCsrfProtectionFilter");
			}

			/* Configure the API server to use the NIO connectors */
			ServerConnector apiConnector = createSelectChannelConnectorForClient(server, clientAcceptors);

			server.addConnector(apiConnector);

			server.setStopAtShutdown(true);
			serverForAgent.setStopAtShutdown(true);
//todo remove      springAppContext.start();

			String osType = getServerOsType();
			if (osType == null || osType.isEmpty()) {
				throw new RuntimeException(Configuration.OS_VERSION.getKey() + " is not "
					+ " set in the ambari.properties file");
			}

			//Start action scheduler
			LOG.info("********* Initializing Clusters **********");
			Clusters clusters = injector.getInstance(Clusters.class);
			StringBuilder clusterDump = new StringBuilder();
			//TODO temporally commented because takes a lot of time on 5k cluster
			//clusters.debugDump(clusterDump);

			LOG.info("********* Current Clusters State *********");
			LOG.info(clusterDump.toString());

			LOG.info("********* Reconciling Alert Definitions **********");
			ambariMetaInfo.reconcileAlertDefinitions(clusters, false);

			LOG.info("********* Initializing ActionManager **********");
			ActionManager manager = injector.getInstance(ActionManager.class);

			LOG.info("********* Initializing Controller **********");
			AmbariManagementController controller = injector.getInstance(
				AmbariManagementController.class);

			LOG.info("********* Initializing Scheduled Request Manager **********");
			ExecutionScheduleManager executionScheduleManager = injector
				.getInstance(ExecutionScheduleManager.class);

			MetricsService metricsService = injector.getInstance(
				MetricsService.class);

			clusterController = controller;

			StateRecoveryManager recoveryManager = injector.getInstance(
				StateRecoveryManager.class);

			recoveryManager.doWork();
			/*
			 * Start the server after controller state is recovered.
			 */
			server.start();
			handlerList.shareSessionCacheToViews(sessionHandler.getSessionCache());

			//views initialization will reset inactive interval with default value, so we should set it after
			sessionHandlerConfigurer.configureMaxInactiveInterval(sessionHandler);

			serverForAgent.start();
			LOG.info("********* Started Server **********");

			if (!configs.isViewDirectoryWatcherServiceDisabled()) {
				LOG.info("Starting View Directory Watcher");
				viewDirectoryWatcher.start();
			}

			manager.start();
			LOG.info("********* Started ActionManager **********");

			executionScheduleManager.start();
			LOG.info("********* Started Scheduled Request Manager **********");

			serviceManager.startAsync();
			LOG.info("********* Started Services **********");

			if (!configs.isMetricsServiceDisabled()) {
				metricsService.start();
			} else {
				LOG.info("AmbariServer Metrics disabled.");
			}

			server.join();
			LOG.info("Joined the Server");
		} catch (BadPaddingException bpe) {
			LOG.error("Bad keystore or private key password. " +
				"HTTPS certificate re-importing may be required.");
			throw bpe;
		} catch (BindException bindException) {
			LOG.error("Could not bind to server port - instance may already be running. " +
				"Terminating this instance.", bindException);
			throw bindException;
		}
	}

	public void stop() throws Exception {
		if (server == null) {
			throw new AmbariException("Error stopping the server");
		} else {
			try {
				server.stop();
			} catch (Exception e) {
				LOG.error("Error stopping the server", e);
			}
		}
	}

	/**
	 * installs bridge handler which redirects log entries from JUL to Slf4J
	 */
	private void setupJulLogging() {
		// install handler for jul to slf4j translation
		LogManager.getLogManager().reset();
		SLF4JBridgeHandler.install();
	}

	/**
	 * Deprecated. Instead, use {@link StaticallyInject}.
	 * <p/>
	 * Static injection replacement to wait Persistence Service start.
	 * @see StaticallyInject
	 */
	@Deprecated
	public void performStaticInjection() {
		AgentResource.init(injector.getInstance(HeartBeatHandler.class));
		CertificateDownload.init(injector.getInstance(CertificateManager.class));
		ConnectionInfo.init(injector.getInstance(Configuration.class));
		CertificateSign.init(injector.getInstance(CertificateManager.class));
		GetResource.init(injector.getInstance(ResourceManager.class));
		PersistKeyValueService.init(injector.getInstance(PersistKeyValueImpl.class));
		KeyService.init(injector.getInstance(PersistKeyValueImpl.class));
		BootStrapResource.init(injector.getInstance(BootStrapImpl.class));
		StackAdvisorResourceProvider.init(injector.getInstance(StackAdvisorHelper.class),
			injector.getInstance(Configuration.class));
		StageUtils.setGson(injector.getInstance(Gson.class));
		StageUtils.setTopologyManager(injector.getInstance(TopologyManager.class));
		StageUtils.setConfiguration(injector.getInstance(Configuration.class));
		SecurityFilter.init(injector.getInstance(Configuration.class));
		StackDefinedPropertyProvider.init(injector);
		AbstractControllerResourceProvider.init(injector.getInstance(ResourceProviderFactory.class));
		BlueprintResourceProvider.init(injector.getInstance(BlueprintFactory.class),
			injector.getInstance(BlueprintDAO.class), injector.getInstance(TopologyRequestDAO.class),
			injector.getInstance(SecurityConfigurationFactory.class), injector.getInstance(Gson.class), ambariMetaInfo);
		StackDependencyResourceProvider.init(ambariMetaInfo);
		ClusterResourceProvider.init(injector.getInstance(TopologyManager.class),
			injector.getInstance(TopologyRequestFactoryImpl.class), injector.getInstance(SecurityConfigurationFactory
				.class), injector.getInstance(Gson.class));
		HostResourceProvider.setTopologyManager(injector.getInstance(TopologyManager.class));
		BlueprintFactory.init(injector.getInstance(BlueprintDAO.class));
		BaseClusterRequest.init(injector.getInstance(BlueprintFactory.class));
		AmbariContext.init(injector.getInstance(HostRoleCommandFactory.class));

		PermissionResourceProvider.init(injector.getInstance(PermissionDAO.class));
		ViewPermissionResourceProvider.init(injector.getInstance(PermissionDAO.class));
		PrivilegeResourceProvider.init(injector.getInstance(PrivilegeDAO.class), injector.getInstance(UserDAO.class),
			injector.getInstance(GroupDAO.class), injector.getInstance(PrincipalDAO.class),
			injector.getInstance(PermissionDAO.class), injector.getInstance(ResourceDAO.class));
		UserPrivilegeResourceProvider.init(injector.getInstance(UserDAO.class), injector.getInstance(ClusterDAO.class),
			injector.getInstance(GroupDAO.class), injector.getInstance(ViewInstanceDAO.class), injector.getInstance(Users.class));
		ClusterPrivilegeResourceProvider.init(injector.getInstance(ClusterDAO.class));
		AmbariPrivilegeResourceProvider.init(injector.getInstance(ClusterDAO.class));
		ActionManager.setTopologyManager(injector.getInstance(TopologyManager.class));
		KerberosKeytabController.setKerberosHelper(injector.getInstance(KerberosHelper.class));
		StackAdvisorBlueprintProcessor.init(injector.getInstance(StackAdvisorHelper.class));
		ThreadPoolEnabledPropertyProvider.init(injector.getInstance(Configuration.class));

		BaseService.init(injector.getInstance(RequestAuditLogger.class));

		RetryHelper.init(injector.getInstance(Clusters.class), configs.getOperationsRetryAttempts());

		KerberosIdentityCleaner identityCleaner = injector.getInstance(KerberosIdentityCleaner.class);
		identityCleaner.register();

		configureFileWatcher();
	}

	/**
	 * Creates default users if in-memory database is used
	 */
	@Transactional
	protected void initDB() throws AmbariException {
		if (configs.getPersistenceType() == PersistenceType.IN_MEMORY || dbInitNeeded) {
			LOG.info("Database init needed - creating default data");
			Users users = injector.getInstance(Users.class);

			UserEntity userEntity;

			// Create the admin user
			userEntity = users.createUser("admin", "admin", "admin");
			users.addLocalAuthentication(userEntity, "admin");
			users.grantAdminPrivilege(userEntity);

			// Create a normal user
			userEntity = users.createUser("user", "user", "user");
			users.addLocalAuthentication(userEntity, "user");

			MetainfoEntity schemaVersion = new MetainfoEntity();
			schemaVersion.setMetainfoName(Configuration.SERVER_VERSION_KEY);
			schemaVersion.setMetainfoValue(VersionUtils.getVersionSubstring(ambariMetaInfo.getServerVersion()));

			metainfoDAO.create(schemaVersion);
		}
	}

	/**
	 * The Jetty thread pool consists of three basic types of threads:
	 * <ul>
	 * <li>Acceptors</li>
	 * <li>Selectors</li>
	 * <li>Threads which can actually do stuff</li>
	 * <ul>
	 * The SelectChannelConnector uses the
	 * {@link Runtime#availableProcessors()} as a way to determine how many
	 * acceptors and selectors to create. If the number of processors is too
	 * great, then there will be no threads left to fullfil connection requests.
	 * This method ensures that the pool size is configured correctly, taking into
	 * account the number of available processors (sockets x core x
	 * threads-per-core).
	 * <p/>
	 * If the configured pool size is determined to be too small, then this will
	 * log a warning and increase the pool size to ensure that there are at least
	 * 20 available threads for requests.
	 * @param acceptorThreads          the number of Acceptor threads configured for the connector.
	 * @param threadPoolName           the name of the thread pool being configured (not {@code null}).
	 * @param configuredThreadPoolSize the size of the pool from {@link Configuration}.
	 */
	protected Server configureJettyThreadPool(int acceptorThreads,
	                                          String threadPoolName, int configuredThreadPoolSize) {
		int minumumAvailableThreads = 20;

		// multiply by two since there is 1 selector for every acceptor
		int reservedJettyThreads = acceptorThreads * 2;

		// this is the calculation used by Jetty
		if (configuredThreadPoolSize < reservedJettyThreads + minumumAvailableThreads) {
			int newThreadPoolSize = reservedJettyThreads + minumumAvailableThreads;

			LOG.warn(
				"The configured Jetty {} thread pool value of {} is not sufficient on a host with {} processors. Increasing the value to {}.",
				threadPoolName, configuredThreadPoolSize, Runtime.getRuntime().availableProcessors(),
				newThreadPoolSize);

			configuredThreadPoolSize = newThreadPoolSize;
		}

		LOG.info(
			"Jetty is configuring {} with {} reserved acceptors/selectors and a total pool size of {} for {} processors.",
			threadPoolName, acceptorThreads * 2, configuredThreadPoolSize,
			Runtime.getRuntime().availableProcessors());

		QueuedThreadPool qtp = new QueuedThreadPool(configuredThreadPoolSize);
		qtp.setName(threadPoolName);
		return new Server(qtp);
	}

	/**
	 * Alters system variables on base of Ambari configuration
	 */
	static void setSystemProperties(Configuration configs) {
		// modify location of temporary dir to avoid using default /tmp dir
		System.setProperty("java.io.tmpdir", configs.getServerTempDir());
		if (configs.getJavaVersion() >= 8) {
			System.setProperty("jdk.tls.ephemeralDHKeySize", String.valueOf(configs.getTlsEphemeralDhKeySize()));
		}
	}

	/**
	 * this method executes database consistency check if skip option was not added
	 */
	protected void runDatabaseConsistencyCheck() throws Exception {
		if (System.getProperty("skipDatabaseConsistencyCheck") == null) {
			boolean fixIssues = (System.getProperty("fixDatabaseConsistency") != null);
			try {
				DatabaseConsistencyCheckResult checkResult = DatabaseConsistencyCheckHelper.runAllDBChecks(fixIssues);
				// Writing explicitly to the console is necessary as the python start script expects it.
				System.out.println("Database consistency check result: " + checkResult);
				if (checkResult.isError()) {
					System.exit(1);
				}
			} catch (Throwable ex) {
				// Writing explicitly to the console is necessary as the python start script expects it.
				System.out.println("Database consistency check result: " + DatabaseConsistencyCheckResult.DB_CHECK_ERROR);
				throw new Exception(ex);
			}
		}
	}

	/**
	 * Performs basic configuration of root handler with static values and values
	 * from configuration file.
	 * @param root root handler
	 */
	protected void configureRootHandler(ServletContextHandler root) {
		configureHandlerCompression(root);
		configureAdditionalContentTypes(root);
		root.setContextPath(CONTEXT_PATH);
		root.setErrorHandler(injector.getInstance(AmbariErrorHandler.class));
		root.setMaxFormContentSize(-1);

		/* Configure web app context */
		root.setResourceBase(configs.getWebAppDir());
	}

	/**
	 * Performs GZIP compression configuration of the context handler
	 * with static values and values from configuration file
	 * @param context handler
	 */
	protected void configureHandlerCompression(ServletContextHandler context) {
		if (configs.isApiGzipped()) {
			FilterHolder gzipFilter = context.addFilter(GzipFilter.class, "/*",
				EnumSet.of(DispatcherType.REQUEST));

			gzipFilter.setInitParameter("methods", "GET,POST,PUT,DELETE");
			gzipFilter.setInitParameter("excludePathPatterns", ".*(\\.woff|\\.ttf|\\.woff2|\\.eot|\\.svg)");
			gzipFilter.setInitParameter("mimeTypes",
				"text/html,text/plain,text/xml,text/css,application/x-javascript," +
					"application/xml,application/x-www-form-urlencoded," +
					"application/javascript,application/json");
			gzipFilter.setInitParameter("minGzipSize", configs.getApiGzipMinSize());
		}
	}

	/**
	 * Create org.eclipse.jetty.server.nio.SelectChannelConnector
	 * implementation for SSL or non-SSL based on configuration.
	 * @param port           connector port
	 * @param needClientAuth one-way / two-way SSL
	 * @return org.eclipse.jetty.server.nio.SelectChannelConnector
	 */
	@SuppressWarnings("deprecation")
	private ServerConnector createSelectChannelConnectorForAgent(Server server, int port, boolean needClientAuth, int acceptors) {
		Map<String, String> configsMap = configs.getConfigsMap();
		ServerConnector agentConnector;

		if (configs.getAgentSSLAuthentication()) {
			String keystore = configsMap.get(Configuration.SRVR_KSTR_DIR.getKey()) + File.separator
				+ configsMap.get(Configuration.KSTR_NAME.getKey());

			String truststore = configsMap.get(Configuration.SRVR_KSTR_DIR.getKey()) + File.separator
				+ configsMap.get(Configuration.TSTR_NAME.getKey());

			String srvrCrtPass = configsMap.get(Configuration.SRVR_CRT_PASS.getKey());

			HttpConfiguration https_config = new HttpConfiguration();
			https_config.addCustomizer(new SecureRequestCustomizer());
			https_config.setRequestHeaderSize(configs.getHttpRequestHeaderSize());
			https_config.setResponseHeaderSize(configs.getHttpResponseHeaderSize());
			https_config.setSendServerVersion(false);

			// Secured connector - default constructor sets trustAll = true for certs
			SslContextFactory sslContextFactory = new SslContextFactory();
			disableInsecureProtocols(sslContextFactory);
			sslContextFactory.setKeyStorePath(keystore);
			sslContextFactory.setTrustStorePath(truststore);
			sslContextFactory.setKeyStorePassword(srvrCrtPass);
			sslContextFactory.setKeyManagerPassword(srvrCrtPass);
			sslContextFactory.setTrustStorePassword(srvrCrtPass);
			sslContextFactory.setKeyStoreType(configsMap.get(Configuration.KSTR_TYPE.getKey()));
			sslContextFactory.setTrustStoreType(configsMap.get(Configuration.TSTR_TYPE.getKey()));
			sslContextFactory.setNeedClientAuth(needClientAuth);
			ServerConnector agentSslConnector = new ServerConnector(server, acceptors, -1,
				new SslConnectionFactory(sslContextFactory, HttpVersion.HTTP_1_1.toString()),
				new HttpConnectionFactory(https_config));
			agentConnector = agentSslConnector;
		} else {
			agentConnector = new ServerConnector(server, acceptors, -1);
			agentConnector.setIdleTimeout(configs.getConnectionMaxIdleTime());
		}

		agentConnector.setPort(port);

		return agentConnector;
	}

	/**
	 * For loading requestlog handlers
	 */
	private static void loadRequestlogHandler(AmbariHandlerList handlerList, Server serverForAgent, Map<String, String> configsMap) {

		//Example:  /var/log/ambari-server/ambari-server-access-yyyy_mm_dd.log
		String requestlogpath = configsMap.get(Configuration.REQUEST_LOGPATH.getKey());

		//Request logs can be disable by removing the property from ambari.properties file
		if (!StringUtils.isBlank(requestlogpath)) {
			String logfullpath = requestlogpath + "//" + Configuration.REQUEST_LOGNAMEPATTERN.getDefaultValue();
			LOG.info("********* Initializing request access log: " + logfullpath);
			RequestLogHandler requestLogHandler = new RequestLogHandler();

			NCSARequestLog requestLog = new NCSARequestLog(requestlogpath);

			String retaindays = configsMap.get(Configuration.REQUEST_LOG_RETAINDAYS.getKey());
			int retaindaysInt = Configuration.REQUEST_LOG_RETAINDAYS.getDefaultValue();
			if (retaindays != null && !StringUtils.isBlank(retaindays)) {
				retaindaysInt = Integer.parseInt(retaindays.trim());
			}

			requestLog.setRetainDays(retaindaysInt);
			requestLog.setAppend(true);
			requestLog.setLogLatency(true);
			requestLog.setExtended(true);
			requestLogHandler.setRequestLog(requestLog);
			//Add requestloghandler to existing handlerlist.
			handlerList.addHandler(requestLogHandler);

			//For agent communication.
			HandlerCollection handlers = new HandlerCollection();
			Handler[] handler = serverForAgent.getHandlers();
			if (handler != null) {
				handlers.setHandlers((Handler[]) handler);
				handlers.addHandler(requestLogHandler);
				serverForAgent.setHandler(handlers);
			}

		}
	}

	/**
	 * To change log level without restart.
	 */
	public static void enableLog4jMonitor(Map<String, String> configsMap) {

		String log4jpath = AmbariServer.class.getResource("/" + Configuration.AMBARI_LOG_FILE).toString();
		String monitorDelay = configsMap.get(Configuration.LOG4JMONITOR_DELAY.getKey());
		long monitorDelayLong = Configuration.LOG4JMONITOR_DELAY.getDefaultValue();

		try {
			log4jpath = log4jpath.replace("file:", "");
			if (StringUtils.isNotBlank(monitorDelay)) {
				monitorDelayLong = Long.parseLong(monitorDelay);
			}
			PropertyConfigurator.configureAndWatch(log4jpath, monitorDelayLong);
		} catch (Exception e) {
			LOG.error("Exception in setting log4j monitor delay of {} for {}", monitorDelay, log4jpath, e);
		}
	}

	@SuppressWarnings("deprecation")
	private ServerConnector createSelectChannelConnectorForClient(Server server, int acceptors) {
		Map<String, String> configsMap = configs.getConfigsMap();
		ServerConnector apiConnector;

		HttpConfiguration http_config = new HttpConfiguration();
		http_config.setRequestHeaderSize(configs.getHttpRequestHeaderSize());
		http_config.setResponseHeaderSize(configs.getHttpResponseHeaderSize());
		http_config.setSendServerVersion(false);
		if (configs.getApiSSLAuthentication()) {
			String httpsKeystore = configsMap.get(Configuration.CLIENT_API_SSL_KSTR_DIR_NAME.getKey()) +
				File.separator + configsMap.get(Configuration.CLIENT_API_SSL_KSTR_NAME.getKey());
			String httpsTruststore = configsMap.get(Configuration.CLIENT_API_SSL_KSTR_DIR_NAME.getKey()) +
				File.separator + configsMap.get(Configuration.CLIENT_API_SSL_TSTR_NAME.getKey());
			LOG.info("API SSL Authentication is turned on. Keystore - " + httpsKeystore);

			String httpsCrtPass = configsMap.get(Configuration.CLIENT_API_SSL_CRT_PASS.getKey());

			HttpConfiguration https_config = new HttpConfiguration(http_config);
			https_config.addCustomizer(new SecureRequestCustomizer());
			https_config.setSecurePort(configs.getClientSSLApiPort());

			SslContextFactory contextFactoryApi = new SslContextFactory();
			disableInsecureProtocols(contextFactoryApi);
			contextFactoryApi.setKeyStorePath(httpsKeystore);
			contextFactoryApi.setTrustStorePath(httpsTruststore);
			contextFactoryApi.setKeyStorePassword(httpsCrtPass);
			contextFactoryApi.setKeyManagerPassword(httpsCrtPass);
			contextFactoryApi.setTrustStorePassword(httpsCrtPass);
			contextFactoryApi.setKeyStoreType(configsMap.get(Configuration.CLIENT_API_SSL_KSTR_TYPE.getKey()));
			contextFactoryApi.setTrustStoreType(configsMap.get(Configuration.CLIENT_API_SSL_KSTR_TYPE.getKey()));
			apiConnector = new ServerConnector(server, acceptors, -1,
				new SslConnectionFactory(contextFactoryApi, HttpVersion.HTTP_1_1.toString()),
				new HttpConnectionFactory(https_config));
			apiConnector.setPort(configs.getClientSSLApiPort());
		} else {
			apiConnector = new ServerConnector(server, acceptors, -1, new HttpConnectionFactory(http_config));
			apiConnector.setPort(configs.getClientApiPort());
		}
		apiConnector.setIdleTimeout(configs.getConnectionMaxIdleTime());

		return apiConnector;
	}

	public String getServerOsType() {
		return configs.getServerOsType();
	}

	private void configureFileWatcher() {
		AmbariEventPublisher ambariEventPublisher = injector.getInstance(AmbariEventPublisher.class);
		Configuration config = injector.getInstance(Configuration.class);
		SingleFileWatch watch = new SingleFileWatch(config.getConfigFile(), file -> ambariEventPublisher.publish(new AmbariPropertiesChangedEvent()));
		watch.start();
	}

	private void configureAdditionalContentTypes(ServletContextHandler root) {
		root.getMimeTypes().addMimeMapping("woff", "application/font-woff");
		root.getMimeTypes().addMimeMapping("ttf", "application/font-sfnt");
	}

	/**
	 * Disables insecure protocols and cipher suites (exact list is defined
	 * at server properties)
	 */
	private void disableInsecureProtocols(SslContextFactory factory) {
		// by default all protocols should be available
		factory.setExcludeProtocols();
		factory.setIncludeProtocols(new String[]{"SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2"});

		if (!configs.getSrvrDisabledCiphers().isEmpty()) {
			String[] masks = configs.getSrvrDisabledCiphers().split(DISABLED_ENTRIES_SPLITTER);
			factory.setExcludeCipherSuites(masks);
		}
		if (!configs.getSrvrDisabledProtocols().isEmpty()) {
			String[] masks = configs.getSrvrDisabledProtocols().split(DISABLED_ENTRIES_SPLITTER);
			factory.setExcludeProtocols(masks);
		}
	}

	/**
	 * Initialize the view registry singleton instance.
	 */
	public void initViewRegistry() {
		ViewRegistry.initInstance(viewRegistry);
	}

}
