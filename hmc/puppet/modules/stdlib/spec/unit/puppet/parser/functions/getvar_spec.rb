#
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
#
require 'puppet'

# We don't need this for the basic tests we're doing
# require 'spec_helper'

# Dan mentioned that Nick recommended the function method call
# to return the string value for the test description.
# this will not even try the test if the function cannot be
# loaded.
describe Puppet::Parser::Functions.function(:getvar) do

  # Pulled from Dan's create_resources function
  def get_scope
    @topscope = Puppet::Parser::Scope.new
    # This is necessary so we don't try to use the compiler to discover our parent.
    @topscope.parent = nil
    @scope = Puppet::Parser::Scope.new
    @scope.compiler = Puppet::Parser::Compiler.new(Puppet::Node.new("floppy", :environment => 'production'))
    @scope.parent = @topscope
    @compiler = @scope.compiler
  end

  describe 'when calling getvar from puppet' do

    it "should not compile when no arguments are passed" do
      Puppet[:code] = 'getvar()'
      get_scope
      expect { @scope.compiler.compile }.should raise_error(Puppet::ParseError, /wrong number of arguments/)
    end
    it "should not compile when too many arguments are passed" do
      Puppet[:code] = 'getvar("foo::bar", "baz")'
      get_scope
      expect { @scope.compiler.compile }.should raise_error(Puppet::ParseError, /wrong number of arguments/)
    end

    it "should lookup variables in other namespaces" do
      pending "Puppet doesn't appear to think getvar is an rvalue function... BUG?"
      Puppet[:code] = <<-'ENDofPUPPETcode'
        class site::data { $foo = 'baz' }
        include site::data
        $foo = getvar("site::data::foo")
        if $foo != 'baz' {
          fail('getvar did not return what we expect')
        }
      ENDofPUPPETcode
      get_scope
      @scope.compiler.compile
    end

  end

end

